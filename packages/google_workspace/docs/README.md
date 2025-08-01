# Google Workspace Integration

The Google Workspace integration collects and parses data from the different [Google Workspace audit reports APIs](https://developers.google.com/admin-sdk/reports/reference/rest).

These blogs from our Security Labs will help you know more about the Google Workspace and how to it setup:

1. To understand what Google Workspace is in [Part One - Surveying the Land](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
2. To set it up, step by step, in [Part Two - Setup Threat Detection with Elastic](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

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
| [Chrome](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/chrome) | The Chrome activity reports return information about Chrome browser and Chrome OS events. |
| [Data Studio](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/data-studio) | Track and audit user interactions and changes made to Looker Studio assets. |
| [Calendar](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/calendar) | The Calendar activity report returns information about how your account's users manage and modify their Google Calendar events. |
| [Chat](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/chat) | The Chat activity report returns information about how your account's users use and manage Spaces. |
| [Vault](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/vault) | The Vault activity report returns information about various types of Vault Audit activity events. |
| [Meet](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/meet) | The Meet activity report returns information about various aspects of call events. |
| [Keep](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/keep) | The Keep activity report returns information about how your account's users manage and modify their notes. |

## Requirements

In order to ingest data from the Google Reports API you must:

- Have an *administrator account*.
- [Set up a ServiceAccount](https://support.google.com/workspacemigrate/answer/9222993?hl=en) using the administrator account.
- [Set up access to the Admin SDK API](https://support.google.com/workspacemigrate/answer/9222865?hl=en) for the ServiceAccount.
- [Enable Domain-Wide Delegation](https://developers.google.com/admin-sdk/reports/v1/guides/delegation) for your ServiceAccount.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly`

Once you have downloaded your service account credentials as a JSON file, you are ready to set up your integration.

Click the Advanced option of Google Workspace Audit Reports. The default value of "API Host" is `https://www.googleapis.com`. The API Host will be used for collecting `access_transparency`, `admin`, `calendar`, `chat`, `chrome`, `context_aware_access`, `data_studio`, `device`, `drive`, `gcp`, `groups`, `group_enterprise`, `keep`, `login`, `meet`, `rules`, `saml`, `token`, `user accounts` and `vault` logs.

>  NOTE: The `Delegated Account` value in the configuration, is expected to be the email of the administrator account, and not the email of the ServiceAccount.

# Google Workspace Gmail Logs

The integration collects and parses Gmail audit logs data available for reporting in Google Workspace. You must first export Google Workspace logs to Google BigQuery. This involves exporting all activity log events and usage reports to Google BigQuery. Only certain Google Workspace editions support this features. For more details see [About reporting logs and BigQuery](https://support.google.com/a/answer/9079364?hl=en). The integration uses the [BigQuery API](https://cloud.google.com/bigquery/docs/reference/rest) to query logs from BigQuery.

## Requirements

In order to ingest data from the Google BigQuery API, you must:

1. Enable BigQuery API if not already

- In the [Google Cloud console](https://console.cloud.google.com), navigate to **APIs & Services > Library**.
- Search for **BigQuery API** and select it.
- Click **Enable**.

2. Create a service account:

- In the [Google Cloud console](https://console.cloud.google.com), navigate to **APIs & Services > Credentials**.
- Click Create **Credentials > Service account**.
- In the setup:
  - Enter a name for the service account.
  - Click **Create and Continue**.
  - (Optional) Grant project access.
  - Click **Continue**.
  - (Optional) Grant user access.
  - Click **Done**.

3. Generate a JSON Key:

- From the **Credentials** page, click on the name of your new service account.
- Go to the **Keys** tab.
- Click **Add Key > Create new key**.
- Choose **JSON** format and click **Create**.
- Save the downloaded JSON key securely.

4. Grant IAM Role to service account:

- Go to **IAM & Admin > IAM** in the Cloud Console.
- Click **Grant access**.
- Paste the service account email in the **New principals** field.
- Click **Select a role**, search for and select **BigQuery Job User**.
- Click **Save**.

5. Set up a BigQuery project for reporting logs

- Go to **IAM & Admin page** for your project.
- Add a project editor for your project.
  - Click **Grant access**.
  - Enter `gapps-reports@system.gserviceaccount.com` in the **New principals** field.
  - In **Select a role**, select **Project**, then **Editor**.
  - Click **Save**.
- Add a Google Workspace administrator account as a project editor by following the same steps above.
- For more details see [Set up a BigQuery project for reporting logs](https://support.google.com/a/answer/9082756?hl=en)

5. Set up a BigQuery Export configuration:

- Sign in to your [Google Admin console](https://admin.google.com) with a super administrator account.
- Navigate to **Reporting > Data Integrations** (Requires having the **Reports** administrator privilege).  
  Education administrators go to Menu **Reporting > BigQuery export**, which opens the **Data integrations** page.
- Point to the **BigQuery Export** card and click Edit.
- To activate BigQuery logs, check the **Enable Google Workspace data export to Google BigQuery** box.
- (Optional) To export sensitive parameters of DLP rules, check the **Allow export of sensitive content from DLP rule logs** box.
- Under **BigQuery project ID**, select the project where you want to store the logs.  
  Choose a project for which `gapps-reports@system.gserviceaccount.com` has an editor role.
- Under **New dataset within project**, enter the name of the dataset to use for storing the logs in the project.  
  A new dataset will be created with this name in your BigQuery project.
- (Optional) Check the **Restrict the dataset to a specific geographic location** box > select the location from the menu.
- Click **Save**.
- For more details see [Set up a BigQuery Export configuration](https://support.google.com/a/answer/9079365?hl=en).

6. Grant Dataset Permissions:

- Go to [Google Cloud console](https://console.cloud.google.com) and search for **BigQuery**.
- Click your Google Cloud project on the left pane.
- Locate the dataset, click the **three-dot menu > Share > Manage Permissions**.
- Click **Add principal**.
- Paste the service account email in **New principals**.
- Select **BigQuery Data Viewer** as the role.
- Click **Save**.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/bigquery`

Once you have downloaded your service account credentials as a JSON file, you are ready to set up your integration for collecting Gmail logs.

>  NOTE: For Gmail data stream, the default value of "BigQuery API Host" is `https://bigquery.googleapis.com`. The BigQuery API Host will be used for collecting gmail logs only.

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

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Logs

### Google Workspace Reports ECS fields

This is a list of Google Workspace Reports fields that are mapped to ECS that are common to all data sets.

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
| google_workspace.login.sensitive_action_name |  | keyword |
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
| google_workspace.admin.alert.id |  | keyword |
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
| google_workspace.admin.chart.filters |  | keyword |
| google_workspace.admin.chart.name |  | keyword |
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
| google_workspace.admin.investigation.action |  | keyword |
| google_workspace.admin.investigation.data_source |  | keyword |
| google_workspace.admin.investigation.entity_ids |  | keyword |
| google_workspace.admin.investigation.object_identifier |  | keyword |
| google_workspace.admin.investigation.query |  | keyword |
| google_workspace.admin.investigation.url_display_text |  | keyword |
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
| google_workspace.actor.application_name | Name of the application used to perform the action. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.drive.accessed_url | The URLs that were accessed. | keyword |
| google_workspace.drive.actor_is_collaborator_account | Whether the actor is a collaborator account. | boolean |
| google_workspace.drive.added_role | Added membership role of a user/group in a Team Drive. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.api_method | The API method used to generate the event. | keyword |
| google_workspace.drive.billable | Whether this activity is billable. | boolean |
| google_workspace.drive.copy_type | Indicates whether the original item and new item are owned by the same organization. | keyword |
| google_workspace.drive.deletion_reason | The reason an item was deleted. | keyword |
| google_workspace.drive.destination_folder_id |  | keyword |
| google_workspace.drive.destination_folder_title |  | keyword |
| google_workspace.drive.encryption_enforcement_option | The client-side encryption policy being applied to the user at time of the item's creation. | keyword |
| google_workspace.drive.file.id |  | keyword |
| google_workspace.drive.file.owner.email |  | keyword |
| google_workspace.drive.file.owner.is_shared_drive | Boolean flag denoting whether owner is a shared drive. | boolean |
| google_workspace.drive.file.type | Document Drive type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.is_encrypted | Whether the file is client-side encrypted. | boolean |
| google_workspace.drive.membership_change_type | Type of change in Team Drive membership of a user/group. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.new_publish_visibility | New Publish Visibility Value. | keyword |
| google_workspace.drive.new_value | When a setting or property of the file changes, the new value for it will appear here. | keyword |
| google_workspace.drive.old_publish_visibility | Old Publish Visibility Value. | keyword |
| google_workspace.drive.old_value | When a setting or property of the file changes, the old value for it will appear here. | keyword |
| google_workspace.drive.old_visibility | When visibility changes, this holds the old value. | keyword |
| google_workspace.drive.originating_app_id | The Google Cloud Project ID of the application that performed the action. | keyword |
| google_workspace.drive.owner_is_team_drive | Whether the owner is a Team Drive. | boolean |
| google_workspace.drive.primary_event | Whether this is a primary event. A single user action in Drive may generate several events. | boolean |
| google_workspace.drive.removed_role | Removed membership role of a user/group in a Team Drive. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.script_id | The document ID of the executing script. | keyword |
| google_workspace.drive.shared_drive_id | The unique identifier of the Team Drive. Only populated for for events relating to a Team Drive or item contained inside a Team Drive. | keyword |
| google_workspace.drive.shared_drive_settings_change_type | Type of change in Team Drive settings. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.sheets_import_range_recipient_doc | Doc ID of the recipient of a sheets import range. | keyword |
| google_workspace.drive.source_folder_id |  | keyword |
| google_workspace.drive.source_folder_title |  | keyword |
| google_workspace.drive.target | Target user or group. | keyword |
| google_workspace.drive.target_domain | The domain for which the access scope was changed. This can also be the alias all to indicate the access scope was changed for all domains that have visibility for this document. | keyword |
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
| google_workspace.alert.data.rule.violation_info.triggered.action.info | Metadata related to the triggered actions. | nested |
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
| google_workspace.device.last_sync_audit_date |  | date |
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
| google_workspace.token.product_bucket |  | keyword |
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


### Chrome

This is the `chrome` dataset.

An example event for `chrome` looks as following:

```json
{
    "@timestamp": "2024-12-09T14:18:25.405Z",
    "agent": {
        "ephemeral_id": "22ff6e77-fce6-4e45-bc2d-52ade8e25589",
        "id": "32a76848-9087-44d6-9609-47bbf0751dd4",
        "name": "elastic-agent-93760",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "google_workspace.chrome",
        "namespace": "88541",
        "type": "logs"
    },
    "device": {
        "model": {
            "name": "NXKUTSI002429051947600"
        }
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "32a76848-9087-44d6-9609-47bbf0751dd4",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "browser_extension_install",
        "agent_id_status": "verified",
        "dataset": "google_workspace.chrome",
        "id": "-3640711002716937498",
        "ingested": "2025-04-22T12:02:30Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"kalpesh.kumar@example.io\",\"profileId\":\"109689693170624712102\"},\"etag\":\"\\\"CfV-pEPVZc7PJf2fWsHJTliD34MdGbO8iFIk3L4uBwQ/cBsNSJx2A9Lg8kiQCGLddmq827A\\\"\",\"events\":{\"name\":\"BROWSER_EXTENSION_INSTALL\",\"parameters\":[{\"intValue\":\"1733753905405\",\"name\":\"TIMESTAMP\"},{\"name\":\"EVENT_REASON\",\"value\":\"BROWSER_EXTENSION_INSTALL\"},{\"name\":\"APP_ID\",\"value\":\"lmjegmlicamnimmfhcmpkclmigmmcbeh\"},{\"name\":\"APP_NAME\",\"value\":\"Application Launcher For Drive (by Google)\"},{\"name\":\"BROWSER_VERSION\",\"value\":\"123.0.6312.112\"},{\"name\":\"CHROME_ORG_UNIT_ID\",\"value\":\"02gajno12larrqx\"},{\"name\":\"CLIENT_TYPE\",\"value\":\"CHROME_OS_DEVICE\"},{\"name\":\"DEVICE_NAME\",\"value\":\"NXKUTSI002429051947600\"},{\"name\":\"DEVICE_PLATFORM\",\"value\":\"ChromeOS 15786.48.2\"},{\"name\":\"DEVICE_USER\",\"value\":\"kalpesh.kumar@example.io\"},{\"name\":\"DIRECTORY_DEVICE_ID\",\"value\":\"efa9510f-8cd2-4d85-b6c2-939cfb335e9e\"},{\"name\":\"EVENT_RESULT\",\"value\":\"REPORTED\"},{\"name\":\"EXTENSION_ACTION\",\"value\":\"INSTALL\"},{\"name\":\"EXTENSION_SOURCE\",\"value\":\"CHROME_WEBSTORE\"},{\"name\":\"EXTENSION_VERSION\",\"value\":\"3.10\"},{\"name\":\"ORG_UNIT_NAME\",\"value\":\"example.io\"},{\"name\":\"PROFILE_USER_NAME\",\"value\":\"kalpesh.kumar@example.io\"},{\"name\":\"USER_AGENT\",\"value\":\"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\"},{\"name\":\"VIRTUAL_DEVICE_ID\",\"value\":\"3d69c5a5-0afc-474b-a1a3-d3dc617e2a60\"}],\"type\":\"BROWSER_EXTENSION_INSTALL_TYPE\"},\"id\":{\"applicationName\":\"chrome\",\"customerId\":\"C03puekhd\",\"time\":\"2024-12-09T14:18:25.405Z\",\"uniqueQualifier\":\"-3640711002716937498\"},\"kind\":\"admin#reports#activity\"}",
        "outcome": "success",
        "provider": "chrome",
        "reason": "BROWSER_EXTENSION_INSTALL"
    },
    "google_workspace": {
        "chrome": {
            "actor": {
                "caller_type": "USER",
                "email": "kalpesh.kumar@example.io",
                "profile_id": "109689693170624712102"
            },
            "app_id": "lmjegmlicamnimmfhcmpkclmigmmcbeh",
            "app_name": "Application Launcher For Drive (by Google)",
            "browser_version": "123.0.6312.112",
            "chrome_org_unit_id": "02gajno12larrqx",
            "client_type": "CHROME_OS_DEVICE",
            "device_name": "NXKUTSI002429051947600",
            "device_platform": "ChromeOS 15786.48.2",
            "device_user": "kalpesh.kumar@example.io",
            "directory_device_id": "efa9510f-8cd2-4d85-b6c2-939cfb335e9e",
            "etag": "\"CfV-pEPVZc7PJf2fWsHJTliD34MdGbO8iFIk3L4uBwQ/cBsNSJx2A9Lg8kiQCGLddmq827A\"",
            "event_reason": "BROWSER_EXTENSION_INSTALL",
            "event_result": "REPORTED",
            "extension_action": "INSTALL",
            "extension_source": "CHROME_WEBSTORE",
            "extension_version": "3.10",
            "id": {
                "application_name": "chrome",
                "customer_id": "C03puekhd",
                "time": "2024-12-09T14:18:25.405Z",
                "unique_qualifier": "-3640711002716937498"
            },
            "kind": "admin#reports#activity",
            "name": "BROWSER_EXTENSION_INSTALL",
            "org_unit_name": "example.io",
            "profile_user_name": "kalpesh.kumar@example.io",
            "timestamp": "2024-12-09T14:18:25.405Z",
            "type": "BROWSER_EXTENSION_INSTALL_TYPE",
            "user_agent": "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "virtual_device_id": "3d69c5a5-0afc-474b-a1a3-d3dc617e2a60"
        }
    },
    "host": {
        "os": {
            "full": "ChromeOS 15786.48.2"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Chrome",
        "vendor": "Google Workspace"
    },
    "organization": {
        "id": "C03puekhd"
    },
    "related": {
        "user": [
            "kalpesh.kumar@example.io",
            "109689693170624712102"
        ]
    },
    "source": {
        "user": {
            "domain": "example.io",
            "email": "kalpesh.kumar@example.io",
            "id": "109689693170624712102",
            "name": "kalpesh.kumar"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-chrome"
    ],
    "user": {
        "domain": "example.io",
        "email": "kalpesh.kumar@example.io",
        "id": "109689693170624712102",
        "name": "kalpesh.kumar"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "os": {
            "full": "Chrome OS 14541.0.0",
            "name": "Chrome OS",
            "version": "14541.0.0"
        },
        "version": "123.0.0.0"
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
| google_workspace.chrome.actor.caller_type |  | keyword |
| google_workspace.chrome.actor.email |  | keyword |
| google_workspace.chrome.actor.key |  | keyword |
| google_workspace.chrome.actor.profile_id |  | keyword |
| google_workspace.chrome.app_id |  | keyword |
| google_workspace.chrome.app_name | App name. | keyword |
| google_workspace.chrome.browser_version | Browser version event parameter. | keyword |
| google_workspace.chrome.chrome_org_unit_id |  | keyword |
| google_workspace.chrome.client_type | Event client type parameter. | keyword |
| google_workspace.chrome.content_hash | Content hash event parameter. | keyword |
| google_workspace.chrome.content_name | Content name event parameter. | keyword |
| google_workspace.chrome.content_size | Content size event parameter. | long |
| google_workspace.chrome.content_transfer_method | The method for content transferring. | keyword |
| google_workspace.chrome.content_type | Content type event parameter. | keyword |
| google_workspace.chrome.device_id | Device id event name. | keyword |
| google_workspace.chrome.device_name | Device name event parameter. | keyword |
| google_workspace.chrome.device_platform | Device platform event parameter. | keyword |
| google_workspace.chrome.device_user | Device user name event parameter. | keyword |
| google_workspace.chrome.directory_device_id | Directory API device ID of the device or browser on which the event happened. | keyword |
| google_workspace.chrome.etag |  | keyword |
| google_workspace.chrome.event_reason | Event reason event parameter. | keyword |
| google_workspace.chrome.event_result | Event result event parameter. | keyword |
| google_workspace.chrome.evidence_locker_filepath | A parameter that contains the filepath of the evidence locker. | keyword |
| google_workspace.chrome.extension_action |  | keyword |
| google_workspace.chrome.extension_source |  | keyword |
| google_workspace.chrome.extension_version |  | keyword |
| google_workspace.chrome.federated_origin | A parameter that contains the domain of the federated 3rd party provding the login flow. | keyword |
| google_workspace.chrome.id.application_name |  | keyword |
| google_workspace.chrome.id.customer_id |  | keyword |
| google_workspace.chrome.id.time |  | date |
| google_workspace.chrome.id.unique_qualifier |  | keyword |
| google_workspace.chrome.ip_address |  | ip |
| google_workspace.chrome.is_federated | A parameter that contains whether the login is through a federated 3rd party. | boolean |
| google_workspace.chrome.kind |  | keyword |
| google_workspace.chrome.login_failure_reason | Login failure event reason parameter. | keyword |
| google_workspace.chrome.login_user_name | A Parameter that contains the username used by the user when performing the login that triggered the login event report. | keyword |
| google_workspace.chrome.name |  | keyword |
| google_workspace.chrome.new_boot_mode | New device boot mode. | keyword |
| google_workspace.chrome.org_unit_name | Org unit name. | keyword |
| google_workspace.chrome.owner_domain |  | keyword |
| google_workspace.chrome.previous_boot_mode | Previous device boot mode. | keyword |
| google_workspace.chrome.profile_user_name | GSuite user name of the profile. | keyword |
| google_workspace.chrome.remove_user_reason | Parameter explaining why a user was removed from a device. | keyword |
| google_workspace.chrome.scan_id | A parameter that contains the scan id of the content analysis scan which triggered the event. | keyword |
| google_workspace.chrome.server_scan_status | Status indicates the outcome of the event's server scan, which could be complete, require a manual audit due to configuration settings, or require a manual audit because the scan took too long. | keyword |
| google_workspace.chrome.timestamp | The server timestamp of the Chrome Safe Browsing event. | date |
| google_workspace.chrome.trigger_destination | A parameter that contains the destination of the rule which triggered the event. | keyword |
| google_workspace.chrome.trigger_source | A parameter that contains the source of the rule which triggered the event. | keyword |
| google_workspace.chrome.trigger_type | Event trigger type parameter. | keyword |
| google_workspace.chrome.trigger_user | Trigger user event parameter. | keyword |
| google_workspace.chrome.triggered_rules_reason | Triggered rules reason event parameter. | keyword |
| google_workspace.chrome.type |  | keyword |
| google_workspace.chrome.url | The URL that event happened on. | keyword |
| google_workspace.chrome.user_agent | User agent event parameter. | keyword |
| google_workspace.chrome.user_justification | A parameter that contains a justification message provided by users. | keyword |
| google_workspace.chrome.virtual_device_id | Virtual device ID of the browser on which the event happened. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Data Studio

This is the `data_studio` dataset.

An example event for `data_studio` looks as following:

```json
{
    "@timestamp": "2025-03-26T09:47:49.748Z",
    "agent": {
        "ephemeral_id": "b77a02e9-85bf-41aa-9b44-811d3c8bf3b4",
        "id": "3b862dd5-96d5-421f-b5a0-887b788df98e",
        "name": "elastic-agent-92555",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "google_workspace.data_studio",
        "namespace": "12604",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "3b862dd5-96d5-421f-b5a0-887b788df98e",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "delete-distribution-content",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "google_workspace.data_studio",
        "id": "1",
        "ingested": "2025-04-22T12:03:39Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":\"1\"},\"events\":{\"name\":\"DELETE_DISTRIBUTION_CONTENT\",\"parameters\":[{\"name\":\"ASSET_ID\",\"value\":\"abc-123\"},{\"name\":\"ASSET_NAME\",\"value\":\"[Sample]ReportName\"},{\"name\":\"OWNER_EMAIL\",\"value\":\"foo@bar.com\"},{\"name\":\"ASSET_TYPE\",\"value\":\"REPORT\"},{\"name\":\"VISIBILITY\",\"value\":\"PEOPLE_WITHIN_DOMAIN_WITH_LINK\"},{\"name\":\"PARENT_WORKSPACE_ID\",\"value\":\"\"},{\"name\":\"CONNECTOR_TYPE\",\"value\":\"\"},{\"name\":\"DISTRIBUTION_CONTENT_NAME\",\"value\":\"[Sample]ReportName\"},{\"name\":\"DISTRIBUTION_CONTENT_OWNER_EMAIL\",\"value\":\"foo@bar.com\"},{\"name\":\"DISTRIBUTION_CONTENT_ID\",\"value\":\"abc-123\"},{\"name\":\"DISTRIBUTION_CONTENT_TYPE\",\"value\":\"SCHEDULE\"}],\"type\":\"ACCESS\"},\"id\":{\"applicationName\":\"data_studio\",\"customerId\":\"1\",\"time\":\"2025-03-26T09:47:49.748Z\",\"uniqueQualifier\":\"1\"},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\"}",
        "provider": "data_studio",
        "type": [
            "deletion"
        ]
    },
    "google_workspace": {
        "actor": {
            "caller_type": "USER"
        },
        "data_studio": {
            "asset_id": "abc-123",
            "asset_name": "[Sample]ReportName",
            "asset_type": "REPORT",
            "distribution_content_id": "abc-123",
            "distribution_content_name": "[Sample]ReportName",
            "distribution_content_owner_email": "foo@bar.com",
            "distribution_content_type": "SCHEDULE",
            "name": "DELETE_DISTRIBUTION_CONTENT",
            "owner_email": "foo@bar.com",
            "type": "ACCESS",
            "visibility": "PEOPLE_WITHIN_DOMAIN_WITH_LINK"
        },
        "kind": "admin#reports#activity"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Data Studio",
        "vendor": "Google Workspace"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "67.43.156.13"
        ],
        "user": [
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
        "forwarded",
        "google_workspace-data_studio"
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
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| google_workspace.actor.caller_type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile_id | The unique Google Workspace profile ID of the actor. | keyword |
| google_workspace.data_studio.asset_id | The id of the asset affected by the event. | keyword |
| google_workspace.data_studio.asset_name | The name of the asset affected by the event. | keyword |
| google_workspace.data_studio.asset_type | The type of the asset. Possible values are `DATA_SOURCE`, `EXPLORER`, `REPORT`, `WORKSPACE`. | keyword |
| google_workspace.data_studio.connector_type | The type of connector used for data integration. This defines how Data Studio connects to and retrieves data from various sources, such as Google Analytics, Google Sheets, and BigQuery, for reporting and visualization. | keyword |
| google_workspace.data_studio.current_value | The current value for the asset permission. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/data-studio | keyword |
| google_workspace.data_studio.data_export_type | The type of data export. Possible values are `CSV`, `CSV_EXCEL`, `EXTRACTED_DATA_SOURCE`, `SHEETS`. | keyword |
| google_workspace.data_studio.distribution_content_id |  | keyword |
| google_workspace.data_studio.distribution_content_name |  | keyword |
| google_workspace.data_studio.distribution_content_owner_email |  | keyword |
| google_workspace.data_studio.distribution_content_type |  | keyword |
| google_workspace.data_studio.embedded_in_report_id | The ID of the report where the data source is embedded. | keyword |
| google_workspace.data_studio.name |  | keyword |
| google_workspace.data_studio.new_value | The new value for the asset permission. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/data-studio | keyword |
| google_workspace.data_studio.old_value | The old value for the asset permission. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/data-studio | keyword |
| google_workspace.data_studio.owner_email | The email address of the asset owner. | keyword |
| google_workspace.data_studio.parent_workspace_id | The parent workspace ID of the asset. | keyword |
| google_workspace.data_studio.previous_value | The previous value for the asset permission. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/data-studio | keyword |
| google_workspace.data_studio.prior_visibility | The prior Visibility. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/data-studio | keyword |
| google_workspace.data_studio.target_domain | The targeted domain for which the link sharing access type of the asset was changed. | keyword |
| google_workspace.data_studio.target_user_email | The targeted user's email for which the sharing permission has been changed. | keyword |
| google_workspace.data_studio.type |  | keyword |
| google_workspace.data_studio.visibility | The visibility of an asset. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/data-studio | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer_id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Calendar

This is the `calendar` dataset.

An example event for `calendar` looks as following:

```json
{
    "@timestamp": "2025-04-01T07:00:40.262Z",
    "agent": {
        "ephemeral_id": "c496161a-177e-4359-8324-e11405aeeaad",
        "id": "1ab21f00-c503-4805-b1de-01dacd186aef",
        "name": "elastic-agent-44155",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "google_workspace.calendar",
        "namespace": "50432",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "1ab21f00-c503-4805-b1de-01dacd186aef",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "delete-calendar",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "google_workspace.calendar",
        "id": "1",
        "ingested": "2025-04-22T12:01:05Z",
        "kind": "event",
        "original": "{\"actor\":{\"email\":\"foo@bar.com\",\"profileId\":\"1\"},\"etag\":\"abcdefgh/cBsNSJx2A9Lg8kiQCGLddmq827A\",\"events\":{\"name\":\"delete_calendar\",\"parameters\":[{\"name\":\"calendar_id\",\"value\":\"c_abc123@group.calendar.google.com\"},{\"name\":\"api_kind\",\"value\":\"web\"},{\"name\":\"user_agent\",\"value\":\"Mozilla/5.0\"}],\"type\":\"calendar_change\"},\"id\":{\"applicationName\":\"calendar\",\"customerId\":\"1\",\"time\":\"2025-04-01T07:00:40.262Z\",\"uniqueQualifier\":\"1\"},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"elastic.com\"}",
        "provider": "calendar",
        "type": [
            "deletion"
        ]
    },
    "google_workspace": {
        "calendar": {
            "api_kind": "web",
            "name": "delete_calendar",
            "type": "calendar_change"
        },
        "etag": "abcdefgh/cBsNSJx2A9Lg8kiQCGLddmq827A",
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Calendar",
        "vendor": "Google Workspace"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "67.43.156.13"
        ],
        "user": [
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
            "name": "foo@bar.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-calendar"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo@bar.com"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Other",
        "original": "Mozilla/5.0"
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
| google_workspace.actor.caller_type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile_id | The unique Google Workspace profile ID of the actor. | keyword |
| google_workspace.calendar.access_level | The access level for calendar. | keyword |
| google_workspace.calendar.api_kind | Indicates where a request for an action came from. | keyword |
| google_workspace.calendar.country | The country of calendar. | keyword |
| google_workspace.calendar.description | The description of calendar. | keyword |
| google_workspace.calendar.event.appointment_schedule_title | The title of the calendar appointment schedule. | keyword |
| google_workspace.calendar.event.client_side_encrypted | Whether the calendar event is client-side encrypted or not. | keyword |
| google_workspace.calendar.event.end_time | The end time of the event in seconds, stored in unix time. | date |
| google_workspace.calendar.event.grantee_email | The email address of the user for whom the request to transfer event ownership has been made. | keyword |
| google_workspace.calendar.event.guest | The email address of a guest user for an event. | keyword |
| google_workspace.calendar.event.id | The unique identification of an event. | keyword |
| google_workspace.calendar.event.is_recurring | Whether the calendar event is a recurring event. | boolean |
| google_workspace.calendar.event.old_title | If the title of a calendar event has been changed, this is the previous title of the event. | keyword |
| google_workspace.calendar.event.organizer_calendar_id | The calendar Id of the organizer of an event. | keyword |
| google_workspace.calendar.event.recurring | Whether the calendar event is a recurring event. | keyword |
| google_workspace.calendar.event.response_status | The response status of event guest. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/calendar#change_event_guest_response. | keyword |
| google_workspace.calendar.event.start_time | The start time of the event in seconds, stored in unix time. | date |
| google_workspace.calendar.event.title | The title of an event. | keyword |
| google_workspace.calendar.id | Calendar Id of the relevant calendar in context of this action (e.g., the calendar that an event is on, or a calendar being subscribed to). | keyword |
| google_workspace.calendar.interop.error_code | A short human-readable error code / error description in English. | keyword |
| google_workspace.calendar.interop.remote_ews_url | URL of the remote Exchange server that Google Calendar EWS server has contacted. | keyword |
| google_workspace.calendar.location | The location associated with the calendar event. | keyword |
| google_workspace.calendar.name |  | keyword |
| google_workspace.calendar.notification.message_id | The notification message ID. | keyword |
| google_workspace.calendar.notification.method | The method used to trigger a notification. Possible values are `alert`, `default`, `email`, `sms`. | keyword |
| google_workspace.calendar.notification.recipient_email | The notification recipient email address. | keyword |
| google_workspace.calendar.notification.type | The type of a notification. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/calendar#notification_triggered. | keyword |
| google_workspace.calendar.requested_period_end | End of the time window for which the availability was requested. | date |
| google_workspace.calendar.requested_period_start | Start of the time window for which the availability was requested. | date |
| google_workspace.calendar.secs_in_advance |  | long |
| google_workspace.calendar.subscriber_calendar_id | The calendar ID of subscriber. | keyword |
| google_workspace.calendar.timezone | The timezone of calendar. | keyword |
| google_workspace.calendar.title | The title of calendar. | keyword |
| google_workspace.calendar.type |  | keyword |
| google_workspace.calendar.user_agent | The user agent from the request that triggered this action. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer_id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Chat

This is the `chat` dataset.

An example event for `chat` looks as following:

```json
{
    "@timestamp": "2025-03-26T05:55:02.063Z",
    "agent": {
        "ephemeral_id": "afc7ce98-0520-45e0-94c4-64274b308642",
        "id": "411b5487-ebfa-4a91-89da-d7e59f3f1cd2",
        "name": "elastic-agent-11706",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "google_workspace.chat",
        "namespace": "37789",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "411b5487-ebfa-4a91-89da-d7e59f3f1cd2",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "room-name-updated",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "google_workspace.chat",
        "id": "1",
        "ingested": "2025-04-16T08:53:19Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":\"1\"},\"etag\":\"abcdefgh/cBsNSJx2A9Lg8kiQCGLddmq827A/\",\"events\":{\"name\":\"room_name_updated\",\"parameters\":[{\"name\":\"room_id\",\"value\":\"1\"},{\"name\":\"actor\",\"value\":\"foo@bar.com\"},{\"name\":\"room_name\",\"value\":\"TEST3\"},{\"name\":\"external_room\",\"value\":\"DISABLED\"},{\"name\":\"actor_type\",\"value\":\"NON_ADMIN\"},{\"name\":\"conversation_type\",\"value\":\"SPACE\"},{\"name\":\"conversation_ownership\",\"value\":\"INTERNALLY_OWNED\"}],\"type\":\"user_action\"},\"id\":{\"applicationName\":\"chat\",\"customerId\":\"1\",\"time\":\"2025-03-26T05:55:02.063Z\",\"uniqueQualifier\":\"1\"},\"kind\":\"admin#reports#activity\"}",
        "provider": "chat",
        "type": [
            "change"
        ]
    },
    "google_workspace": {
        "actor": {
            "caller_type": "USER"
        },
        "chat": {
            "actor": "foo@bar.com",
            "actor_type": "NON_ADMIN",
            "conversation_ownership": "INTERNALLY_OWNED",
            "conversation_type": "SPACE",
            "external_room": "DISABLED",
            "name": "room_name_updated",
            "room_id": "1",
            "room_name": "TEST3",
            "type": "user_action"
        },
        "etag": "abcdefgh/cBsNSJx2A9Lg8kiQCGLddmq827A/",
        "kind": "admin#reports#activity"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Chat",
        "vendor": "Google Workspace"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "user": [
            "foo@bar.com"
        ]
    },
    "source": {
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo@bar.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-chat"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo@bar.com"
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
| google_workspace.actor.caller_type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile_id | The unique Google Workspace profile ID of the actor. | keyword |
| google_workspace.chat.actor |  | keyword |
| google_workspace.chat.actor_type | Description of the actor type. Possible values are `ADMIN`, `NON_ADMIN`. | keyword |
| google_workspace.chat.attachment_hash | Attachment Hash. | keyword |
| google_workspace.chat.attachment_name | Attachment Name. | keyword |
| google_workspace.chat.attachment_status | Whether there is an attachment associated with the message that the event occurred in. Possible values are `HAS_ATTACHMENT`, `NO_ATTACHMENT`. | keyword |
| google_workspace.chat.attachment_url | The url of chat attachment. | keyword |
| google_workspace.chat.conversation_ownership | Whether the conversation that the event occurred in is owned by the customer or other customers. Possible values are `EXTERNALLY_OWNED`, `INTERNALLY_OWNED`. | keyword |
| google_workspace.chat.conversation_type | The conversation type of the chat that the event occurred in. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/chat. | keyword |
| google_workspace.chat.dlp_scan_status | Description of the status of a data loss prevention (DLP) scan of a message or attachment. For a list of possible values refer to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/chat#message_posted. | keyword |
| google_workspace.chat.emoji_shortcode | Emoji Shortcode. | keyword |
| google_workspace.chat.external_room |  | keyword |
| google_workspace.chat.filename | The file name of an emoji being created or deleted. | keyword |
| google_workspace.chat.message_id |  | keyword |
| google_workspace.chat.message_type | The message type of the message that the event occurred in. For a list of possible values refere to https://developers.google.com/workspace/admin/reports/v1/appendix/activity/chat#message_posted. | keyword |
| google_workspace.chat.name |  | keyword |
| google_workspace.chat.report_id | The full resource name of the report, which can be used to fetch reports via the Chat GET or LIST APIs. | keyword |
| google_workspace.chat.report_type | Description of the report type for a report made in a Space. | keyword |
| google_workspace.chat.retention_state |  | keyword |
| google_workspace.chat.room_id | Room Id. | keyword |
| google_workspace.chat.room_name |  | keyword |
| google_workspace.chat.target_user_role | Description of the new role type. Possible values are `MEMBER`, `SPACE_MANAGER`. | keyword |
| google_workspace.chat.target_users | Target Users. | keyword |
| google_workspace.chat.type |  | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer_id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Vault

This is the `vault` dataset.

An example event for `vault` looks as following:

```json
{
    "@timestamp": "2025-04-10T19:05:24.881Z",
    "agent": {
        "ephemeral_id": "540f8dff-4158-4152-a7b6-757f8019ae43",
        "id": "e5b82ff4-853f-4f9f-9a68-54de01dc5631",
        "name": "elastic-agent-58720",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "google_workspace.vault",
        "namespace": "52776",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "e5b82ff4-853f-4f9f-9a68-54de01dc5631",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "view-per-matter-litigation-hold-report",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "google_workspace.vault",
        "id": "1",
        "ingested": "2025-04-23T06:26:01Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":\"1\"},\"etag\":\"XB4Sd9ZEYpFd-msikcPTLY7Ao7PvyP0QeR9k5OdWZ_Y/77VsZvNcux1EnUIu_SyN08-cHo8\",\"events\":{\"name\":\"view_per_matter_litigation_hold_report\",\"parameters\":[{\"name\":\"matter_id\",\"value\":\"78504485-73d5-4b01-ae1a-63ebc1ae66eb\"},{\"name\":\"resource_name\",\"value\":\"0\"},{\"name\":\"additional_details\",\"value\":\"matter_name: \\\"Demo\\\"\\n\"}],\"type\":\"user_action\"},\"id\":{\"applicationName\":\"vault\",\"customerId\":\"1\",\"time\":\"2025-04-10T19:05:24.881Z\",\"uniqueQualifier\":\"1\"},\"kind\":\"admin#reports#activity\"}",
        "provider": "vault",
        "type": [
            "access"
        ]
    },
    "google_workspace": {
        "actor": {
            "caller_type": "USER"
        },
        "etag": "XB4Sd9ZEYpFd-msikcPTLY7Ao7PvyP0QeR9k5OdWZ_Y/77VsZvNcux1EnUIu_SyN08-cHo8",
        "kind": "admin#reports#activity",
        "vault": {
            "additional_details": {
                "matter_name": "Demo"
            },
            "additional_details_raw": "matter_name: \"Demo\"\n",
            "matter_id": "78504485-73d5-4b01-ae1a-63ebc1ae66eb",
            "name": "view_per_matter_litigation_hold_report",
            "resource_name": "0",
            "type": "user_action"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Vault",
        "vendor": "Google Workspace"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "user": [
            "foo@bar.com"
        ]
    },
    "source": {
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo@bar.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-vault"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo@bar.com"
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
| google_workspace.actor.caller_type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile_id | The unique Google Workspace profile ID of the actor. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer_id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| google_workspace.vault.additional_details.apply_only_to_deleted_objects |  | boolean |
| google_workspace.vault.additional_details.data_region |  | keyword |
| google_workspace.vault.additional_details.export_format |  | keyword |
| google_workspace.vault.additional_details.export_linked_drive_files |  | boolean |
| google_workspace.vault.additional_details.export_name |  | keyword |
| google_workspace.vault.additional_details.matter_name |  | keyword |
| google_workspace.vault.additional_details.period |  | keyword |
| google_workspace.vault.additional_details.query |  | keyword |
| google_workspace.vault.additional_details.show_locker_content |  | boolean |
| google_workspace.vault.additional_details.type |  | keyword |
| google_workspace.vault.additional_details.use_improved_export |  | boolean |
| google_workspace.vault.additional_details_raw | Additional details pertaining to an audit log. | keyword |
| google_workspace.vault.matter_id | The Matter ID an audit pertains to. | keyword |
| google_workspace.vault.name |  | keyword |
| google_workspace.vault.organizational_unit_name | The organizational unit name. | keyword |
| google_workspace.vault.query.mode | The mode of a search. Possible values are All data, Held data, Unprocessed data. | keyword |
| google_workspace.vault.query.terms |  | keyword |
| google_workspace.vault.query.time_zone |  | keyword |
| google_workspace.vault.query.type |  | keyword |
| google_workspace.vault.query_raw | The user inputted query for search and exports. | keyword |
| google_workspace.vault.resource_name | The resource name of the action, such as hold name or saved query name. | keyword |
| google_workspace.vault.resource_url | The document URL of the document view. | keyword |
| google_workspace.vault.target_user | The targeted user (such as user put on hold). | keyword |
| google_workspace.vault.type |  | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Meet

This is the `meet` dataset.

An example event for `meet` looks as following:

```json
{
    "@timestamp": "2025-04-11T09:23:00.703059Z",
    "agent": {
        "ephemeral_id": "7a575721-1942-4427-82ec-22448e27a2d1",
        "id": "eb41b16b-f309-4682-9d3a-30342d680fe9",
        "name": "elastic-agent-32126",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "google_workspace.meet",
        "namespace": "56950",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "eb41b16b-f309-4682-9d3a-30342d680fe9",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "invitation-sent",
        "agent_id_status": "verified",
        "dataset": "google_workspace.meet",
        "id": "1",
        "ingested": "2025-05-05T10:30:54Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":\"1\"},\"etag\":\"abcdefgh/cBsNSJx2A9Lg8kiQCGLddmq827A\",\"events\":{\"name\":\"invitation_sent\",\"parameters\":[{\"boolValue\":false,\"name\":\"is_external\"},{\"name\":\"meeting_code\",\"value\":\"NTBTYDTXBE\"},{\"name\":\"conference_id\",\"value\":\"-PeisjX_5iUtKPuGffkJDaBcdEfgh\"},{\"name\":\"action_time\",\"value\":\"2025-04-11T09:23:00.703059Z\"},{\"intValue\":\"1\",\"name\":\"target_user_count\"},{\"name\":\"identifier\",\"value\":\"foo@bar.com\"},{\"name\":\"identifier_type\",\"value\":\"email_address\"}],\"type\":\"conference_action\"},\"id\":{\"applicationName\":\"meet\",\"customerId\":\"1\",\"time\":\"2025-04-11T09:23:00.703Z\",\"uniqueQualifier\":\"1\"},\"kind\":\"admin#reports#activity\"}",
        "provider": "meet",
        "type": [
            "info"
        ]
    },
    "google_workspace": {
        "actor": {
            "caller_type": "USER"
        },
        "etag": "abcdefgh/cBsNSJx2A9Lg8kiQCGLddmq827A",
        "kind": "admin#reports#activity",
        "meet": {
            "conference_id": "-PeisjX_5iUtKPuGffkJDaBcdEfgh",
            "endpoint": {
                "identifier": "foo@bar.com",
                "identifier_type": "email_address",
                "is_external": false
            },
            "meeting_code": "NTBTYDTXBE",
            "name": "invitation_sent",
            "target": {
                "user_count": 1
            },
            "type": "conference_action"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Meet",
        "vendor": "Google Workspace"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "user": [
            "foo@bar.com"
        ]
    },
    "source": {
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo@bar.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-meet"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo@bar.com"
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
| google_workspace.actor.caller_type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile_id | The unique Google Workspace profile ID of the actor. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer_id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.meet.action_description | The description of a abuse report. | keyword |
| google_workspace.meet.action_reason | The reason for submitting a abuse report. | keyword |
| google_workspace.meet.action_time | The time of an action. | date |
| google_workspace.meet.broadcast_state | The state of this Meet broadcast. | keyword |
| google_workspace.meet.calendar_event_id | The identifier of the Google Calendar event associated with the conference. | keyword |
| google_workspace.meet.conference_id | The unique identifier of the conference. | keyword |
| google_workspace.meet.endpoint.audio.recv_packet_loss_max | The maximum packet loss for received audio streams (percent). | long |
| google_workspace.meet.endpoint.audio.recv_packet_loss_mean | The mean packet loss for received audio streams (percent). | long |
| google_workspace.meet.endpoint.audio.recv_seconds | The duration during which the participant received any audio (seconds). | long |
| google_workspace.meet.endpoint.audio.send_bitrate_kbps_mean | The mean bitrate of the sent audio stream (kbit/s). | long |
| google_workspace.meet.endpoint.audio.send_packet_loss_max | The maximum packet loss for the sent audio stream (percent). | long |
| google_workspace.meet.endpoint.audio.send_packet_loss_mean | The mean packet loss for the sent audio stream (percent). | long |
| google_workspace.meet.endpoint.audio.send_seconds | The duration during which the participant sent audio (seconds). | long |
| google_workspace.meet.endpoint.device_type | The participant's device type. | keyword |
| google_workspace.meet.endpoint.display_name | Human readable name of the endpoint that is displayed in the meeting. | keyword |
| google_workspace.meet.endpoint.duration_seconds | The duration for which the participant stayed in the meeting (seconds). | long |
| google_workspace.meet.endpoint.end_of_call_rating | The call rating given by the participant at the end of the call, ranging from 1 to 5. | long |
| google_workspace.meet.endpoint.id | The unique endpoint identifier for the current call. | keyword |
| google_workspace.meet.endpoint.identifier | The unique participant identifier (for example, an email address, phone number, or device ID). | keyword |
| google_workspace.meet.endpoint.identifier_type | Indicates the type of the participant identifier. | keyword |
| google_workspace.meet.endpoint.ip_address | The participant's external IP address. | ip |
| google_workspace.meet.endpoint.is_external | Indicates if the participant is external to your organization. | boolean |
| google_workspace.meet.endpoint.location_country | The country from which the participant joined. | keyword |
| google_workspace.meet.endpoint.location_region | The city or geographical region within a country from which the participant joined. | keyword |
| google_workspace.meet.endpoint.network.congestion | The fraction of time where the network did not have enough bandwidth to send all the data to Google servers (percent). | long |
| google_workspace.meet.endpoint.network.estimated_download_kbps_mean | The estimated bandwidth used by received media streams (kbps). | long |
| google_workspace.meet.endpoint.network.estimated_upload_kbps_mean | The estimated bandwidth used by sent media streams (kbps). | long |
| google_workspace.meet.endpoint.network.recv_jitter_msec_max | The maximum network jitter for received packets (milliseconds). | long |
| google_workspace.meet.endpoint.network.recv_jitter_msec_mean | The mean network jitter for received packets (milliseconds). | long |
| google_workspace.meet.endpoint.network.rtt_msec_mean | The mean network round-trip time (milliseconds). | long |
| google_workspace.meet.endpoint.network.send_jitter_msec_mean | The mean network jitter for sent packets (milliseconds). | long |
| google_workspace.meet.endpoint.network.transport_protocol | The network protocol that was used. | keyword |
| google_workspace.meet.endpoint.screencast.recv_bitrate_kbps_mean | The mean bitrate of the received screencasts (kbit/s). | long |
| google_workspace.meet.endpoint.screencast.recv_fps_mean | The mean frame rate of received screencasts (FPS). | long |
| google_workspace.meet.endpoint.screencast.recv_long_side_median_pixels | The median of the long side of the received screencasts (pixels). | long |
| google_workspace.meet.endpoint.screencast.recv_packet_loss_max | The maximum packet loss for received screencasts (percent). | long |
| google_workspace.meet.endpoint.screencast.recv_packet_loss_mean | The mean packet loss for received screencasts (percent). | long |
| google_workspace.meet.endpoint.screencast.recv_seconds | The duration during which the participant received any screencast (seconds). | long |
| google_workspace.meet.endpoint.screencast.recv_short_side_median_pixels | The median of the short side of the received screencasts (pixels). | long |
| google_workspace.meet.endpoint.screencast.send_bitrate_kbps_mean | The mean bitrate of sent screencasts (kbit/s). | long |
| google_workspace.meet.endpoint.screencast.send_fps_mean | The mean frame rate of sent screencasts (FPS). | long |
| google_workspace.meet.endpoint.screencast.send_long_side_median_pixels | The median of the long side of the sent screencasts (pixels). | long |
| google_workspace.meet.endpoint.screencast.send_packet_loss_max | The maximum packet loss for sent screencasts (percent). | long |
| google_workspace.meet.endpoint.screencast.send_packet_loss_mean | The mean packet loss for sent screencasts (percent). | long |
| google_workspace.meet.endpoint.screencast.send_seconds | The duration during which the participant sent a screencast (seconds). | long |
| google_workspace.meet.endpoint.screencast.send_short_side_median_pixels | The median of the short side of the sent screencasts (pixels). | long |
| google_workspace.meet.endpoint.start_timestamp_seconds | The time when the participant joined the meeting (in epoch seconds). | long |
| google_workspace.meet.endpoint.video.recv_fps_mean | The mean frame rate of received video streams (FPS). | long |
| google_workspace.meet.endpoint.video.recv_long_side_median_pixels | The median of the long side of the received video streams (pixels). | long |
| google_workspace.meet.endpoint.video.recv_packet_loss_max | The maximum packet loss for received video streams (percent). | long |
| google_workspace.meet.endpoint.video.recv_packet_loss_mean | The mean packet loss for received video streams (percent). | long |
| google_workspace.meet.endpoint.video.recv_seconds | The duration during which the participant received any video (seconds). | long |
| google_workspace.meet.endpoint.video.recv_short_side_median_pixels | The median of the short side of the received video streams (pixels). | long |
| google_workspace.meet.endpoint.video.send_bitrate_kbps_mean | The mean bitrate of the sent video stream (kbit/s). | long |
| google_workspace.meet.endpoint.video.send_fps_mean | The mean frame rate of the sent video stream (FPS). | long |
| google_workspace.meet.endpoint.video.send_long_side_median_pixels | The median of the long side of the sent video stream (pixels). | long |
| google_workspace.meet.endpoint.video.send_packet_loss_max | The maximum packet loss for the sent video stream (percent). | long |
| google_workspace.meet.endpoint.video.send_packet_loss_mean | The mean packet loss for the sent video stream (percent). | long |
| google_workspace.meet.endpoint.video.send_seconds | The duration during which the participant sent video (seconds). | long |
| google_workspace.meet.endpoint.video.send_short_side_median_pixels | The median of the short side of the sent video stream (pixels). | long |
| google_workspace.meet.livestream.endpoint.ecdn_location | The Enterprise Content Delivery Network (eCDN) location for a Meet livestream viewer. | keyword |
| google_workspace.meet.livestream.endpoint.ecdn_network | The eCDN network for a Meet livestream viewer. | keyword |
| google_workspace.meet.livestream.endpoint.private_ip_address | The private IP address for a Meet livestream viewer. | ip |
| google_workspace.meet.livestream.view_page_id | The id for the Meet conference livestream view page. | keyword |
| google_workspace.meet.meeting_code | The meeting code for the Google Meet conference. | keyword |
| google_workspace.meet.name |  | keyword |
| google_workspace.meet.organizer_email | The email address of the meeting creator. | keyword |
| google_workspace.meet.product_type | The type of meeting product (Classic Hangouts/Google Meet). | keyword |
| google_workspace.meet.streaming_session_state | The state of this Meet streaming session. | keyword |
| google_workspace.meet.target.display_names | The target display names for this action. | keyword |
| google_workspace.meet.target.email | The target email for this action. | keyword |
| google_workspace.meet.target.phone_number | The target phone number for this action. | keyword |
| google_workspace.meet.target.user_count | Target user count. | long |
| google_workspace.meet.type |  | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Keep

This is the `keep` dataset.

An example event for `keep` looks as following:

```json
{
    "@timestamp": "2025-03-27T12:45:08.310Z",
    "agent": {
        "ephemeral_id": "e43a76f4-47c9-40b4-b16e-547081b85cca",
        "id": "d2812dfd-bd3b-46f8-b372-9357a26b4580",
        "name": "elastic-agent-49635",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "google_workspace.keep",
        "namespace": "61415",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "d2812dfd-bd3b-46f8-b372-9357a26b4580",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "uploaded-attachment",
        "agent_id_status": "verified",
        "dataset": "google_workspace.keep",
        "id": "0",
        "ingested": "2025-04-29T06:58:21Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":\"1\"},\"etag\":\"abcdefgh-SHfJfeOMlTPu983WfVweBonaAPdmU\",\"events\":{\"name\":\"uploaded_attachment\",\"parameters\":[{\"name\":\"owner_email\",\"value\":\"foo@bar.com\"},{\"name\":\"note_name\",\"value\":\"https://keep.googleapis.com/v1/notes/abc-xyz\"},{\"name\":\"attachment_name\",\"value\":\"https://keep.googleapis.com/v1/notes/abc-xyz/attachments/abcdefgh\"}],\"type\":\"user_action\"},\"id\":{\"applicationName\":\"keep\",\"customerId\":\"1\",\"time\":\"2025-03-27T12:45:08.310Z\",\"uniqueQualifier\":\"0\"},\"kind\":\"admin#reports#activity\"}",
        "provider": "keep",
        "type": [
            "change"
        ]
    },
    "google_workspace": {
        "actor": {
            "caller_type": "USER"
        },
        "etag": "abcdefgh-SHfJfeOMlTPu983WfVweBonaAPdmU",
        "keep": {
            "attachment_name": "https://keep.googleapis.com/v1/notes/abc-xyz/attachments/abcdefgh",
            "name": "uploaded_attachment",
            "note_name": "https://keep.googleapis.com/v1/notes/abc-xyz",
            "owner_email": "foo@bar.com",
            "type": "user_action"
        },
        "kind": "admin#reports#activity"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Keep",
        "vendor": "Google Workspace"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "user": [
            "foo@bar.com"
        ]
    },
    "source": {
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo@bar.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-keep"
    ],
    "url": {
        "full": "https://keep.googleapis.com/v1/notes/abc-xyz"
    },
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo@bar.com"
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
| google_workspace.actor.caller_type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile_id | The unique Google Workspace profile ID of the actor. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer_id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.keep.attachment_name | Attachment resource URI. | keyword |
| google_workspace.keep.name |  | keyword |
| google_workspace.keep.note_name | Note resource URI. | keyword |
| google_workspace.keep.owner_email | Note owner email. | keyword |
| google_workspace.keep.type |  | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Gmail

This is the `gmail` dataset.

An example event for `gmail` looks as following:

```json
{
    "@timestamp": "2025-05-05T07:27:19.747Z",
    "agent": {
        "ephemeral_id": "0423f4ba-e8b1-46ff-83ca-78f7fdf5e6bb",
        "id": "13d359d8-1d2c-40e4-b48c-03e4d73897a7",
        "name": "elastic-agent-66265",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "google_workspace.gmail",
        "namespace": "82186",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "13d359d8-1d2c-40e4-b48c-03e4d73897a7",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "dataset": "google_workspace.gmail",
        "duration": 541484000,
        "ingested": "2025-07-29T05:48:55Z",
        "kind": "event",
        "original": "{\"row\":{\"f\":[{\"v\":{\"f\":[{\"v\":null},{\"v\":\"541484\"},{\"v\":\"0\"},{\"v\":\"true\"},{\"v\":\"1746430039747736\"}]}}]},\"schema\":{\"fields\":[{\"fields\":[{\"fields\":[{\"mode\":\"NULLABLE\",\"name\":\"client_type\",\"type\":\"STRING\"},{\"fields\":[{\"mode\":\"NULLABLE\",\"name\":\"delegate_user_email\",\"type\":\"STRING\"},{\"mode\":\"NULLABLE\",\"name\":\"dusi\",\"type\":\"STRING\"}],\"mode\":\"NULLABLE\",\"name\":\"session_context\",\"type\":\"RECORD\"}],\"mode\":\"NULLABLE\",\"name\":\"client_context\",\"type\":\"RECORD\"},{\"mode\":\"NULLABLE\",\"name\":\"elapsed_time_usec\",\"type\":\"INTEGER\"},{\"mode\":\"NULLABLE\",\"name\":\"mail_event_type\",\"type\":\"INTEGER\"},{\"mode\":\"NULLABLE\",\"name\":\"success\",\"type\":\"BOOLEAN\"},{\"mode\":\"NULLABLE\",\"name\":\"timestamp_usec\",\"type\":\"INTEGER\"}],\"mode\":\"NULLABLE\",\"name\":\"event_info\",\"type\":\"RECORD\"}]}}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "google_workspace": {
        "gmail": {
            "event_info": {
                "elapsed_time_usec": 541484,
                "mail_event_type": "0",
                "success": true,
                "timestamp_usec": 1746430039747736
            }
        }
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-gmail"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| google_workspace.gmail.domain_name |  | keyword |
| google_workspace.gmail.email |  | keyword |
| google_workspace.gmail.event_id |  | keyword |
| google_workspace.gmail.event_info.client_context.client_type | The type of client or device where the action occurred, including WEB, IOS, ANDROID, IMAP, POP3, and API. | keyword |
| google_workspace.gmail.event_info.client_context.session_context.delegate_user_email | Email address of the delegated user who performed the action on the account owner's behalf. | keyword |
| google_workspace.gmail.event_info.client_context.session_context.dusi | Identifier for a user's session on a specific device. | keyword |
| google_workspace.gmail.event_info.elapsed_time_usec | Total time duration of the event, in microseconds. | long |
| google_workspace.gmail.event_info.mail_event_type | Logged event type. The event type corresponds to the Event attribute in Gmail log events in Security Investigation Tool. | keyword |
| google_workspace.gmail.event_info.success | True if the event was successful, otherwise false. For example, the value is false if the message was rejected by a policy. | boolean |
| google_workspace.gmail.event_info.timestamp_usec | Time when this event started, in the form of a UNIX timestamp, in microseconds. | date |
| google_workspace.gmail.event_name |  | keyword |
| google_workspace.gmail.event_type |  | keyword |
| google_workspace.gmail.has_sensitive_content |  | boolean |
| google_workspace.gmail.ip_address |  | ip |
| google_workspace.gmail.message_info.action_type | The message delivery action that the event represents. | keyword |
| google_workspace.gmail.message_info.attachment.file_extension_type | File extension (not mime part type), not including the period. | keyword |
| google_workspace.gmail.message_info.attachment.file_name | File attachment name. | keyword |
| google_workspace.gmail.message_info.attachment.malware_family | Malware category, if detected when the message is handled. This field is unset if no malware is detected. | keyword |
| google_workspace.gmail.message_info.attachment.sha256 | SHA256 hash of the attachment. | keyword |
| google_workspace.gmail.message_info.confidential_mode_info.is_confidential_mode | Indicates whether the message was sent in confidential mode. | boolean |
| google_workspace.gmail.message_info.connection_info.authenticated_domain.name | Authenticated domain name. | keyword |
| google_workspace.gmail.message_info.connection_info.authenticated_domain.type | Message authentication type (for example, SPF, DKIM). | keyword |
| google_workspace.gmail.message_info.connection_info.client_host_zone | Client host zone of the mail sender. | keyword |
| google_workspace.gmail.message_info.connection_info.client_ip | IP address of the mail client that started the message. | ip |
| google_workspace.gmail.message_info.connection_info.dkim_pass | Indicates if the message was authenticated using at least one DKIM signature. | boolean |
| google_workspace.gmail.message_info.connection_info.dmarc_pass | Indicates if the message passed DMARC policy evaluation. | boolean |
| google_workspace.gmail.message_info.connection_info.dmarc_published_domain |  | keyword |
| google_workspace.gmail.message_info.connection_info.failed_smtp_out_connect_ip | List of all IPs in the remote MX record that Gmail attempted to connect to but failed. | ip |
| google_workspace.gmail.message_info.connection_info.ip_geo_city | Nearest city computed based on the relay IP. | keyword |
| google_workspace.gmail.message_info.connection_info.ip_geo_country | ISO country code based on the relay IP. | keyword |
| google_workspace.gmail.message_info.connection_info.is_internal | Indicates if the message was sent within domains owned by the customer. | boolean |
| google_workspace.gmail.message_info.connection_info.is_intra_domain | Indicates if the message was sent within the same domain. | boolean |
| google_workspace.gmail.message_info.connection_info.smtp_in_connect_ip | Remote IP address for MTA client connections (inbound SMTP to Gmail). | ip |
| google_workspace.gmail.message_info.connection_info.smtp_out_connect_ip | Remote IP address for SMTP connections from Gmail. | ip |
| google_workspace.gmail.message_info.connection_info.smtp_out_remote_host | For outgoing SMTP connections, the domain the message started from; the destination domain or the smarthost. | keyword |
| google_workspace.gmail.message_info.connection_info.smtp_reply_code | SMTP reply code for inbound and outbound SMTP connections. Usually 2xx, 4xx, or 5xx. | long |
| google_workspace.gmail.message_info.connection_info.smtp_response_reason | Detailed reason for the SMTP reply code for inbound connections. | keyword |
| google_workspace.gmail.message_info.connection_info.smtp_tls_cipher | Name of the TLS cipher being used for secure connections to the SMTP server. | keyword |
| google_workspace.gmail.message_info.connection_info.smtp_tls_state | Type of connection made to the SMTP server. Only set for logs of events that explicitly handle SMTP connections. | keyword |
| google_workspace.gmail.message_info.connection_info.smtp_tls_version | TLS version used for secure connections to the SMTP server. For example, TLSv1.2. | keyword |
| google_workspace.gmail.message_info.connection_info.smtp_user_agent_ip | IP address of the mail user agent for inbound SMTP connections. | ip |
| google_workspace.gmail.message_info.connection_info.spf_pass | Indicates if the message was authenticated with SP. | boolean |
| google_workspace.gmail.message_info.connection_info.tls_required_but_unavailable | TLS is required for an outbound SMTP connection, but no valid certificate was present. | boolean |
| google_workspace.gmail.message_info.description | Human-readable description of what happened to the message. | keyword |
| google_workspace.gmail.message_info.destination.address | Recipient email address. | keyword |
| google_workspace.gmail.message_info.destination.rcpt_response | Response of the SMTP RCPT command. | keyword |
| google_workspace.gmail.message_info.destination.selector | Subcategory for each service. | keyword |
| google_workspace.gmail.message_info.destination.service | The service at the message destination. | keyword |
| google_workspace.gmail.message_info.destination.smime_decryption_success | For inbound messages only. When set, indicates that S/MIME decryption was attempted for this recipient.The value indicates the completion status. Not set if skipped. | boolean |
| google_workspace.gmail.message_info.destination.smime_extraction_success | For inbound messages only. When set, indicates that S/MIME extraction was attempted for this recipient. The value indicates the completion status. Not set if skipped. | boolean |
| google_workspace.gmail.message_info.destination.smime_parsing_success | For inbound messages only. When set, indicates that S/MIME parsing was attempted for this recipient. The value indicates the completion status. Not set if skipped. | boolean |
| google_workspace.gmail.message_info.destination.smime_signature_verification_success | For inbound messages only. When set, indicates that S/MIME signature verification was attempted for this recipient. The value indicates the completion status. Not set if skipped. | boolean |
| google_workspace.gmail.message_info.flattened_destinations | String that has information of all recipient information flattened, in this format:  `service_for_recipient1:selector_for_recipient1:address_for_recipient1, service_for_recipient2:selector_for_recipient2:address_for_recipient2`. | keyword |
| google_workspace.gmail.message_info.flattened_triggered_rule_info | String that has information of all triggered rules, in JSON format. | keyword |
| google_workspace.gmail.message_info.is_policy_check_for_sender | True if the policy rules were evaluated for the sender (the message was processed for outbound delivery). False if the policy rules were evaluated for the recipient (the message was processed for inbound delivery). | boolean |
| google_workspace.gmail.message_info.is_spam | True if the message was classified as spam. | boolean |
| google_workspace.gmail.message_info.link_domain | Domains extracted from link URLs in the message body. | keyword |
| google_workspace.gmail.message_info.message_set.type | Message set type that the message belongs to. | keyword |
| google_workspace.gmail.message_info.num_message_attachments | Number of message attachments. | long |
| google_workspace.gmail.message_info.payload_size | Size of the message payload, in bytes. | long |
| google_workspace.gmail.message_info.post_delivery_info.action_type | Post-delivery action type. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.data_classification.classified_entity | Entity type that was classified. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.data_classification.event_type | Classification event type. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.data_classification.labels.field_value_display_name | Label display name. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.data_classification.previous_labels.field_value_display_name | Previous label's display name. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.interaction.attachment.file_extension_type | File extension (not MIME part type), not including the period. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.interaction.attachment.file_name | Attachment file name. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.interaction.attachment.malware_family | Malware type, if malware is detected during message handling. If no malware is detected, this field is not set. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.interaction.attachment.sha256 | SHA256 hash of the attachment. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.interaction.drive_id | The unique ID of the Google Drive item associated with the interaction. This ID is used to access the item in Drive. This field is set only for Drive attachment interactions. | keyword |
| google_workspace.gmail.message_info.post_delivery_info.interaction.link_url | The URL associated with the interaction, which is set set only for link click interactions. | keyword |
| google_workspace.gmail.message_info.rfc2822_message_id | RFC 2822 message ID for the message. To see this, select Show Original for the Gmail message. | keyword |
| google_workspace.gmail.message_info.smime_content_type | The top-level S/MIME type of a message, indicated by the Content-Type: header. | keyword |
| google_workspace.gmail.message_info.smime_encrypt_message | For outbound messages only. When set and true, indicates the message should be encrypted. | boolean |
| google_workspace.gmail.message_info.smime_extraction_success | When set, indicates that inbound S/MIME processing occurred. Not set if skipped. The value indicates the completion status. | boolean |
| google_workspace.gmail.message_info.smime_packaging_success | For outbound messages only. When set, indicates that S/MIME packaging was attempted. Not set if skipped. The value indicates the completion status. | boolean |
| google_workspace.gmail.message_info.smime_sign_message | For outbound messages only. When set and true, indicates message should be signed. | boolean |
| google_workspace.gmail.message_info.smtp_relay_error | If Gmail rejects an SMTP relay request, this error code provides information about the cause of the rejection. | keyword |
| google_workspace.gmail.message_info.source.address | Email address of the sender. | keyword |
| google_workspace.gmail.message_info.source.from_header_address | From: header address as it appears in the message headers. | keyword |
| google_workspace.gmail.message_info.source.from_header_displayname | From: header display name as it appears in the message headers, for example, John Doe. This field might be truncated if the log is too long or if there are too many triggered rules (triggered_rule_info) in the log. | keyword |
| google_workspace.gmail.message_info.source.selector | A subcategory of the source server. For value descriptions, go to message_info.source.service. | keyword |
| google_workspace.gmail.message_info.source.service | The source service for the message. | keyword |
| google_workspace.gmail.message_info.spam_info.classification_reason | Reason the message was classified as spam, phishing, or other classification. | keyword |
| google_workspace.gmail.message_info.spam_info.classification_timestamp_usec | Message spam classification timestamp. | date |
| google_workspace.gmail.message_info.spam_info.disposition | The outcome of the Gmail spam classification. | keyword |
| google_workspace.gmail.message_info.spam_info.ip_whitelist_entry | The IP whitelist entry that informed the classification, when the message is classified by a custom rule in Gmail settings. | keyword |
| google_workspace.gmail.message_info.structured_policy_log_info.detected_file_types.category | MIME type category. | keyword |
| google_workspace.gmail.message_info.structured_policy_log_info.detected_file_types.mime_type | File MIME type. | keyword |
| google_workspace.gmail.message_info.structured_policy_log_info.exchange_journal_info.recipients | Domain recipients for the journaled message known to Google. | keyword |
| google_workspace.gmail.message_info.structured_policy_log_info.exchange_journal_info.rfc822_message_id | RFC 822 message ID of the journaled message. | keyword |
| google_workspace.gmail.message_info.structured_policy_log_info.exchange_journal_info.timestamp | The timestamp of the journaled message, in seconds. | date |
| google_workspace.gmail.message_info.structured_policy_log_info.exchange_journal_info.unknown_recipients | Domain recipients unknown to Google for the journaled message. | keyword |
| google_workspace.gmail.message_info.subject | Message subject.This field may be truncated if the log is too long, or the number of triggered rules (triggered_rule_info) in the log is too big. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.consequence.action | Action taken for the consequence. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.consequence.reason | Reason the consequence was applied. Usually contains the unique description of a rule that triggered the consequence. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.consequence.subconsequence.action | Action taken for the sub-consequence. Go to consequence action for a description of possible values. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.consequence.subconsequence.reason | Reason the sub-consequence was applied. Usually contains the unique description of a rule that triggered the consequence. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.policy_holder_address | Email address of the policyholder whose policy triggered the rules. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.rule_name | Custom rule description entered in the Admin console. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.rule_type | Custom rule type. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.spam_label_modifier | Describes the custom rule spam classification results. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.string_match.attachment_name | Name of the attachment where a matching string was found in the text extracted from a binary file. Note: This field is currently not populated. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.string_match.match_expression | Match expression set in the Admin console. This field may be truncated if the log is too long, or the number of triggered rules (triggered_rule_info) in the log is too big. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.string_match.matched_string | String that triggered the rule. Sensitive information is hidden by \* or . This field might be truncated if the log is too long, or the number of triggered rules (triggered_rule_info) in the log is too large. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.string_match.predefined_detector_name | If this was a match of predefined detectors, indicates the name of the predefined detector. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.string_match.source | Location of the string matched in the message. | keyword |
| google_workspace.gmail.message_info.triggered_rule_info.string_match.type | Type of match. | keyword |
| google_workspace.gmail.message_info.upload_error_category | Error encountered while uploading the message to the destination. | keyword |
| google_workspace.gmail.record_type |  | keyword |
| google_workspace.gmail.resource_details.application_id |  | keyword |
| google_workspace.gmail.resource_details.applied_labels.field_values.display_name | Field display name. | keyword |
| google_workspace.gmail.resource_details.applied_labels.field_values.id | Field ID. | keyword |
| google_workspace.gmail.resource_details.applied_labels.field_values.selection_value.badged | Indicates whether the choice is badged. | boolean |
| google_workspace.gmail.resource_details.applied_labels.field_values.selection_value.display_name | Choice display name. | keyword |
| google_workspace.gmail.resource_details.applied_labels.field_values.selection_value.id | Choice ID. | keyword |
| google_workspace.gmail.resource_details.applied_labels.field_values.type | Always SELECTION because Gmail currently supports only a selection field. | keyword |
| google_workspace.gmail.resource_details.applied_labels.id | Label ID. | keyword |
| google_workspace.gmail.resource_details.applied_labels.title | Label title. | keyword |
| google_workspace.gmail.resource_details.id | RFC 2822 message ID of the message. Set only when the message has labels. | keyword |
| google_workspace.gmail.resource_details.relation |  | keyword |
| google_workspace.gmail.resource_details.title | Message subject. Set only set when the message has labels. | keyword |
| google_workspace.gmail.resource_details.type | Always EMAIL for Gmail events. | keyword |
| google_workspace.gmail.time_usec |  | date |
| google_workspace.gmail.unique_identifier |  | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |

