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

The integration collects and parses Gmail audit logs data available for reporting in Google Workspace. You must first export Google Workspace logs to Google BigQuery. This involves exporting all activity log events and usage reports to Google BigQuery. Only certain Google Workspace editions support this feature. For more details see [About reporting logs and BigQuery](https://support.google.com/a/answer/9079364?hl=en). The integration uses the [BigQuery API](https://cloud.google.com/bigquery/docs/reference/rest) to query logs from BigQuery.

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

{{event "saml"}}

{{fields "saml"}}

### User Accounts

This is the `user_accounts` dataset.

{{event "user_accounts"}}

{{fields "user_accounts"}}

### Login Accounts

This is the `login` dataset.

{{event "login"}}

{{fields "login"}}

### Rules

This is the `rules` dataset.

{{event "rules"}}

{{fields "rules"}}

### Admin

This is the `admin` dataset.

{{event "admin"}}

{{fields "admin"}}

### Drive

This is the `drive` dataset.

{{event "drive"}}

{{fields "drive"}}

### Groups

This is the `groups` dataset.

{{event "groups"}}

{{fields "groups"}}

### Alert

This is the `alert` dataset.

{{event "alert"}}

{{fields "alert"}}

### Device

This is the `device` dataset.

{{event "device"}}

{{fields "device"}}

### Group Enterprise

This is the `group_enterprise` dataset.

{{event "group_enterprise"}}

{{fields "group_enterprise"}}

### Token

This is the `token` dataset.

{{event "token"}}

{{fields "token"}}

### Access Transparency

This is the `access_transparency` dataset.

{{event "access_transparency"}}

{{fields "access_transparency"}}

### Context Aware Access

This is the `context_aware_access` dataset.

{{event "context_aware_access"}}

{{fields "context_aware_access"}}

### GCP

This is the `gcp` dataset.

{{event "gcp"}}

{{fields "gcp"}}

### Chrome

This is the `chrome` dataset.

{{event "chrome"}}

{{fields "chrome"}}

### Data Studio

This is the `data_studio` dataset.

{{event "data_studio"}}

{{fields "data_studio"}}

### Calendar

This is the `calendar` dataset.

{{event "calendar"}}

{{fields "calendar"}}

### Chat

This is the `chat` dataset.

{{event "chat"}}

{{fields "chat"}}

### Vault

This is the `vault` dataset.

{{event "vault"}}

{{fields "vault"}}

### Meet

This is the `meet` dataset.

{{event "meet"}}

{{fields "meet"}}

### Keep

This is the `keep` dataset.

{{event "keep"}}

{{fields "keep"}}

### Gmail

This is the `gmail` dataset.

{{event "gmail"}}

{{fields "gmail"}}
