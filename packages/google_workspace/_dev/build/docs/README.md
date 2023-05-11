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
