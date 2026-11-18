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
| [Gmail Reports](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/gmail) | The Gmail activity report returns information about message delivery, SMTP connections, spam classification and policy rule matches. |
| [Gemini](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps) | The Gemini in Workspace Apps activity report returns information about generative AI feature usage across Workspace applications. |

## Requirements

In order to ingest data from the Google Reports API you must:

- Have an *administrator account*. As a security best practice, instead of using a Super Admin account, you can create a custom role with the following permissions. This applies the principle of least privilege.

  **Admin console privileges**
  - OUs: Read
  - Users: Read
  - Chrome Management > Managed browsers: Read
  - Chrome Management > Manage ChromeOS Devices: Read (only needed for the `chromeos_devices` data stream; *Managed browsers: Read* does not grant it)
  - View Reports
  - Alert Center: Full access

  **Admin API privileges**
  - Reports
  - Groups: Read
  - OU: Read
  - Users: Read

  You also need to enable the following APIs in your Google Cloud project:
  - Admin SDK API
  - Google Workspace Alert Center API
- [Set up a ServiceAccount](https://support.google.com/workspacemigrate/answer/9222993?hl=en) using the administrator account.
- [Set up access to the Admin SDK API](https://support.google.com/workspacemigrate/answer/9222865?hl=en) for the ServiceAccount.
- [Enable Domain-Wide Delegation](https://developers.google.com/admin-sdk/reports/v1/guides/delegation) for your ServiceAccount.

The Reports API data streams use the following *oauth2 scope*:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly`

The `users`, `group_inventory` and `chromeos_devices` data streams need different scopes. See the Google Workspace Users, Google Workspace Groups inventory and Google Workspace ChromeOS Devices sections.

### Inventory data streams

Most data streams of this integration contain audit **events** from the Reports API: what happened. Three data streams instead contain an **inventory** from the Admin SDK Directory API: what exists, collected again in full on every cycle, with `event.kind: asset`. All three are turned off by default.

| Inventory data stream | Contains | Related audit data streams |
|---|---|---|
| `users` | One document per user account | `user_accounts`, `admin` |
| `group_inventory` | One document per Google group | `groups`, `group_enterprise` |
| `chromeos_devices` | One document per enrolled ChromeOS device | `chrome` |

Once you have downloaded your service account credentials as a JSON file, you are ready to set up your integration.

Click the Advanced option of Google Workspace Audit Reports. The default value of "API Host" is `https://www.googleapis.com`. The API Host will be used for collecting `access_transparency`, `admin`, `calendar`, `chat`, `chrome`, `context_aware_access`, `data_studio`, `device`, `drive`, `gcp`, `gemini`, `gmail_reports`, `groups`, `group_enterprise`, `keep`, `login`, `meet`, `rules`, `saml`, `token`, `user accounts` and `vault` logs.

>  NOTE: The `Delegated Account` value in the configuration, is expected to be the email of the administrator account, and not the email of the ServiceAccount.

### Collection window settings for Reports API data streams

The `access_transparency`, `admin`, `context_aware_access`, `device`, `drive`, `gcp`, `groups`, `group_enterprise`, `login`, `rules`, `saml`, `token` and `user_accounts` data streams request activity from the Reports API in time windows. Three settings control those windows:

- **Initial Interval** (package level, default `24h`): how far back the first collection reaches when a data stream starts with no saved position.
- **Lag Time** (per data stream, default `2h`): how far behind the current time the end of every window stays. Google publishes activity with a delay that varies by report; see [Data retention and lag times](https://support.google.com/a/answer/7061566). Events newer than `now - Lag Time` are not requested yet, and are collected on a later interval once they have settled.
- **Chunk Duration** (per data stream, under Advanced options, disabled by default): the maximum span of activity requested in one interval. When set, each interval requests a window of at most this duration starting from the last completed position, and the position only moves forward after the whole window has been collected. If collection is interrupted, for example by an agent restart or a policy update, only that one chunk is requested again.

Without Chunk Duration, an interval requests everything from the last completed position up to `now - Lag Time` in a single window. For a data stream with a large backlog or a high event rate, such as `token` or `drive` on a busy domain, that window can take longer to page through than the time between interruptions. Each interruption then restarts the same window from the beginning, no progress is saved, and the data stream appears to stall while it re-sends events it has already sent.

Recommended Chunk Duration values:

| Data stream volume | Suggested value |
|---|---|
| High (for example `token`, `drive`, `login` on large domains) | `1h` |
| Moderate | `6h` |
| Low (for example `rules`, `saml`, `access_transparency`) | `24h` |

A chunk should be small enough to be fully collected between the interruptions you expect, and must not exceed `720h` (30 days). Once the data stream has caught up, the window end is limited by `now - Lag Time`, so Chunk Duration has no effect on steady-state collection. Leaving the setting empty, or setting it to `0`, disables chunking. Existing saved positions are reused unchanged when the setting is turned on or off.

### Duplicate events and index rollover

The `access_transparency`, `admin`, `chat`, `context_aware_access`, `device`, `drive`, `gcp`, `group_enterprise`, `groups`, `login`, `rules`, `saml`, `token` and `user_accounts` data streams set the document `_id` to a fingerprint of the event's `id` and `events` fields, so collecting the same event twice normally produces one document. The `alert` data stream does the same with a fingerprint of the alert's identifiers and timestamps. The other data streams let Elasticsearch generate the `_id`, so every re-collected event from them is stored again.

The fingerprint prevents duplicates only within one backing index. A data stream checks for an existing `_id` only in its current write index, so if the data stream rolls over between the first and second collection of an event, the second copy is stored in the new backing index. Two documents with the same `_id` in different backing indices are the sign of this. The backing index rolls over by size or by age according to the data stream's lifecycle policy, and a large replay can trigger a size-based rollover by itself within hours.

For example, with Chunk Duration unset and a saved position several weeks old, the next interval requests those weeks in one window. If the agent restarts partway through, the whole window is requested again, and any events that were already indexed before a rollover are indexed a second time. With Chunk Duration set to `1h`, the same saved position produces one hour of activity per interval, and a restart re-collects at most that hour, so at most one hour of events can be duplicated if a rollover happens in between.

To limit duplicates, set Chunk Duration on busy data streams, and keep Initial Interval no longer than the history you need when a data stream starts with no saved position. If you do need a long initial history, set Chunk Duration as well so it is collected one chunk at a time.

# Google Workspace Gmail Logs

:::{note}
The integration provides two Gmail data streams. This section is for `gmail`, which queries logs exported to Google BigQuery. If you prefer the Google Reports API, enable `gmail_reports` instead — it shares the service account and `admin.reports.audit.readonly` scope used by the other Reports API streams and skips the BigQuery configuration steps below.
:::

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

# Google Workspace ChromeOS Devices

The `chromeos_devices` data stream collects an **inventory** of the ChromeOS and ChromeOS Flex devices enrolled in your Google Workspace or Chrome Enterprise account, from the [Admin SDK Directory API](https://developers.google.com/workspace/admin/directory/reference/rest/v1/chromeosdevices/list). Each collection cycle produces one document per device, describing what exists: identity, status, organizational unit, assigned user, OS version and update state, boot mode, TPM, end of auto-updates, last known IP addresses and recent users. Documents have `event.kind: asset`.

This is different from the `chrome` data stream, which contains Chrome and ChromeOS activity **events** (what happened). Changes made to devices by administrators are in the `admin` data stream.

The data stream is turned off by default.

## Collection

The Directory API has no filter for changed devices, so each cycle reads the whole device inventory again. The default interval is `24h`. Each request returns up to 100 devices (the **Page Size** setting, which Google allows up to 300).

To collect only part of the inventory, set **Organizational Unit** under the data stream's advanced options. The data stream then collects the devices in that organizational unit and all its children. Use the full path, for example `/Sales` (the leading `/` is optional), or `id:` followed by the organizational unit ID.

## Requirements

The `chromeos_devices` data stream uses the same service account and `Delegated Account` as the Reports API data streams. It needs this extra scope and privilege:

| OAuth scope to add | Privilege the delegated account needs |
|---|---|
| `https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly` | Services → Chrome Management → Manage ChromeOS Devices → **Manage ChromeOS Devices (read only)**, on **all** organizational units, and Organizational Units → Read |

*Chrome Management → Managed browsers: Read* is a different privilege for Chrome browsers. It does not give access to ChromeOS devices. Google has merged the former "Admin console privileges" and "Admin API privileges" into one **Admin privileges** section, so one grant covers both. See [Delegate admin roles in Chrome](https://support.google.com/chrome/a/answer/2984343).

To add the scope to the service account's domain-wide delegation (a super administrator must do this):

1. In the Admin console go to **Security → Access and data control → API controls → Manage Domain Wide Delegation**.
2. Find the service account's client ID and click **Edit**. Do not use **Add new** for a client ID that is already listed, and do not delete and re-add it: deleting it stops every application that uses it straight away.
3. Add the scope. **Keep** `https://www.googleapis.com/auth/admin.reports.audit.readonly` and any other scopes already listed.
4. Click **Authorize**, then open **View details** and check that the scope is listed.

Use the exact scope string in the table. Google does not accept a broader scope in place of the one the integration requests. Scope changes can take up to 24 hours to take effect. If your organization uses multi-party approval, another super administrator must approve the change first.

> NOTE: If the scope is not delegated yet, Google issues no token and the `chromeos_devices` data stream collects nothing. The other data streams of the integration are not affected.

Devices only appear after they are enrolled, and enrolment needs a ChromeOS Enterprise, Education or Kiosk & Signage upgrade for each device, including ChromeOS Flex devices. An account without enrolled devices collects no documents, and this is not an error.

Hardware, network and recent-user information is only reported while the *User and device reporting* policies are on. They are on by default. See [View ChromeOS device details](https://support.google.com/chrome/a/answer/1698333).

The data stream calls `https://admin.googleapis.com`. You can change this with the **Directory API Host** setting under the data stream's advanced options. If your network uses an egress allowlist, add `admin.googleapis.com`.

## Notes on the data

- Devices in every status are included, among them deprovisioned and disabled devices. `host.entity.attributes.managed` is set from `status`:

  | `status` | `host.entity.attributes.managed` |
  |---|---|
  | `ACTIVE`, `DISABLED` | `true` |
  | `DEPROVISIONED`, `INACTIVE`, `DELINQUENT`, `PRE_PROVISIONED` | `false` |
  | `RETURN_REQUESTED`, `RETURN_ARRIVED`, `SHIPPED`, `UNKNOWN`, absent or any other value | not set |

- ChromeOS devices have no hostname. `host.name` is the serial number, or else the device ID. The asset ID set by an administrator goes in `host.entity.display_name`.
- The assigned user (`google_workspace.chromeos_devices.annotated_user`) is free text that administrators can edit. It is copied to `user.email`, `user.name` and `user.domain` only when it is an email address.
- `host.ip` holds the devices' local IP addresses. The public (WAN) addresses are shared by many devices behind the same NAT, so they are only in `related.ip` and `google_workspace.chromeos_devices.last_known_network.wan_ip_address`.
- Google returns some values in either camelCase or upper case, for example `chromeOs` or `CHROME_OS`. They are kept as received.
- Telemetry reports, such as CPU, memory, disk volume and active time reports, are not indexed. They are only in `event.original` when **Preserve original event** is on.

## Troubleshooting

- **The data stream stops with `oauth2: cannot fetch token` and the input health is Degraded.** Google rejected the token request. The error usually contains `unauthorized_client`, `access_denied`, `invalid_grant`, `invalid_scope` or `admin_policy_enforced`. Check that the scope is delegated exactly as in the table above, and that enough time has passed for the change to take effect.
- **An error document reports HTTP 403 `Not Authorized to access this resource/api`.** The delegated account lacks the *Manage ChromeOS Devices (read only)* privilege.
- **Fewer devices than expected.** The delegated account's Chrome privilege is probably limited to some organizational units. Grant it on all organizational units. Also check the **Organizational Unit** setting.
- **No devices at all.** The account has no enrolled ChromeOS devices, or no ChromeOS upgrades.

# Google Workspace Users

The `users` data stream collects an **inventory** of the user accounts in your Google Workspace tenant from the [Admin SDK Directory API](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list). Each collection cycle produces one document per user, describing what exists: identity, 2-Step Verification, admin, suspension and archive state, organizational unit, manager and other directory attributes. Documents have `event.kind: asset`.

This is different from the `user_accounts` data stream, which contains audit **events** about actions users took on their own accounts (what happened). Changes to users made by administrators are in the `admin` data stream.

The data stream is turned off by default.

## Collection

The Directory API has no filter for changed users, so each cycle reads the whole directory again. The default interval is `24h`. A tenant of 50,000 users needs about 100 requests per cycle.

Two optional settings add more information to each user document. Both are off by default:

- **Collect group membership** adds the groups each user is a direct member of (`user.group.id`, `user.group.name` and `google_workspace.users.groups`). Membership inherited through nested groups is not included. It also links each user to the groups they own (`user.entity.relationships.owns.entity.id`) and manage (added to `user.entity.relationships.administers.entity.id`). These IDs are the `entity.id` of the group documents in the `group_inventory` data stream. The Entity Store graph draws `owns` links from Kibana 9.4 and `administers` links from Kibana 9.5.
- **Collect admin roles and privileges** adds the admin roles assigned to each user (`user.roles`), their privileges (`user.entity.attributes.permissions`) and the scope each role applies to (`user.entity.relationships.administers.entity.id`): an organizational unit ID, or the customer ID for roles that apply to the whole account, such as super administrator. The full assignments are in `google_workspace.users.role_assignments`. Only roles assigned **directly** to the user are included. Roles a user gets through a group are not, because the Directory API only returns those for a single user at a time.

`user.roles` always includes `super_admin` or `delegated_admin` when Google flags the user as one, even when the roles option is off.

When an option is on and its requests succeed, every user document carries `google_workspace.users.groups` or `google_workspace.users.role_assignments`, as an empty list (`[]`) if the user has no direct membership or assignment. When the option is off, or its requests failed in that cycle, the field is left out of the document, and a failure also produces an error document. Elasticsearch does not index empty lists, so the difference is visible in the document source but cannot be used in a query.

## Requirements

The `users` data stream uses the same service account and `Delegated Account` as the Reports API data streams. It needs these extra scopes and privileges:

| Setting | OAuth scope to add | Privilege the delegated account needs |
|---|---|---|
| Always | `https://www.googleapis.com/auth/admin.directory.user.readonly` | Users → Read and Organizational Units → Read, on **all** organizational units |
| Collect group membership | `https://www.googleapis.com/auth/admin.directory.group.readonly` | Groups → Read. If you use a Groups Reader or Groups Editor role assignment instead, it must cover all groups. |
| Collect admin roles and privileges | `https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly` | The delegated account must be a **super administrator**. Google does not offer a privilege that grants read access to admin roles, so other accounts get HTTP 403 on these requests. |

Google has merged the former "Admin console privileges" and "Admin API privileges" into one **Admin privileges** section, so one *Users → Read* privilege covers both. See [Administrator privilege definitions](https://support.google.com/a/answer/1219251).

To add the scopes to the service account's domain-wide delegation (a super administrator must do this):

1. In the Admin console go to **Security → Access and data control → API controls → Manage Domain Wide Delegation**.
2. Find the service account's client ID and click **Edit**. Do not use **Add new** for a client ID that is already listed, and do not delete and re-add it: deleting it stops every application that uses it straight away.
3. Add the scopes you need, separated by commas. **Keep** `https://www.googleapis.com/auth/admin.reports.audit.readonly` and any other scopes already listed.
4. Click **Authorize**, then open **View details** and check that every scope is listed.

Use the exact scope strings in the table. Google does not accept a broader scope in place of the one the integration requests. Scope changes can take up to 24 hours to take effect. If your organization uses multi-party approval, another super administrator must approve the change first.

> NOTE: The integration requests all the scopes the data stream needs in one token request. If any of them is not delegated yet, Google issues no token and the **whole** `users` data stream stops, including the basic user inventory. Turn on an optional setting only after its scope is delegated and in effect. The other data streams of the integration are not affected.

The data stream calls `https://admin.googleapis.com`. You can change this with the **Directory API Host** setting under the data stream's advanced options. If your network uses an egress allowlist, add `admin.googleapis.com`.

## Notes on the data

- `user.entity.lifecycle.last_activity` comes from the user's last sign-in time. Google says this value "might be inaccurate" when listing all users, so treat it as approximate. Users who have never signed in have no value. `google_workspace.users.agreed_to_terms: false` also shows that a user has never completed a first sign-in.
- Deleted users are not included.

## Troubleshooting

- **The data stream stops with `oauth2: cannot fetch token` and the input health is Degraded.** Google rejected the token request. The error usually contains `unauthorized_client`, `access_denied`, `invalid_grant`, `invalid_scope` or `admin_policy_enforced`. Check that every scope for the settings you enabled is delegated exactly as in the table above, and that enough time has passed for the change to take effect.
- **An error document reports HTTP 403 on a roles, role assignments, groups or members request.** The delegated account lacks the privilege for that option. Users are still collected, without that information. For the roles option, the delegated account must be a super administrator.
- **Fewer users than expected.** The delegated account's role is probably limited to some organizational units. Grant Users → Read on all organizational units.

# Google Workspace Groups inventory

The `group_inventory` data stream collects an **inventory** of the Google groups in your Google Workspace account from the [Admin SDK Directory API](https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list). Each collection cycle produces one document per group, describing what exists: the group's email, name, aliases and member count, its owners and managers, the groups nested in it, its external members and, optionally, its access settings and admin roles. Documents have `event.kind: asset`.

This is different from the `groups` and `group_enterprise` data streams, which contain Groups audit **events** (what happened), such as a member being added or a setting being changed.

The data stream is turned off by default.

## Collection

The Directory API has no filter for changed groups, so each cycle lists every group and reads every group's direct members again. The default interval is `24h`. A cycle needs one request per 200 groups, plus at least one request per group for its members (one per 200 members). The `users` data stream reads the same group members when its Collect group membership option is on, and both data streams share the Directory API quota of the delegated account with the Reports API data streams.

Each group document contains:

- `group.id` and `group.name`, and the group as an entity: `entity.id` (the group ID), `entity.name` (the group email), `entity.display_name` and `entity.sub_type: google_workspace_group`. ECS has no entity type for groups, so `entity.type` is not set. From Kibana 9.4 the Entity Store keeps each group as a generic entity.
- The owners and managers (`google_workspace.group_inventory.owners` and `managers`, also in `related.user`), the groups that are direct members of this group (`member_groups`), the external members (`external_members`), whether the whole account is a member (`has_customer_member`) and member counts by type and role (`member_counts`).
- The plain user members are **not** listed on group documents. They are on the user documents of the `users` data stream (`user.group.id`) when its Collect group membership option is on. `group.id` on a group document is the same value as `user.group.id` on a user document.

Two optional settings add more information to each group document. Both are off by default:

- **Collect group settings** adds the group's access settings from the [Groups Settings API](https://developers.google.com/workspace/admin/groups-settings/v1/reference/groups) under `google_workspace.group_inventory.settings`: who can join, post, view members, view and find the group, whether external members are allowed, moderation and others. It costs one more request per group, against the Groups Settings API quota of 100,000 requests a day per Google Cloud project. At the default `24h` interval that covers about 90,000 groups, and at `1h` about 4,000. When the quota is used up, settings are not requested again in that cycle, one error document is published and the remaining group documents carry `google_workspace.group_inventory.settings_error`. These are the values set on the group. Organization-wide Groups for Business sharing settings can restrict them further and are not included.
- **Collect admin roles and privileges** adds the admin roles assigned directly to each group (`google_workspace.group_inventory.role_assignments`), their privileges (`entity.attributes.permissions`) and, for roles limited to an organizational unit, that unit's ID (`entity.relationships.administers.entity.id`). The members of such a group hold the role through the group.

## Requirements

The `group_inventory` data stream uses the same service account and `Delegated Account` as the Reports API data streams. It needs these extra scopes and privileges:

| Setting | OAuth scope to add | Privilege the delegated account needs |
|---|---|---|
| Always | `https://www.googleapis.com/auth/admin.directory.group.readonly` | Groups → Read. If you use a Groups Reader or Groups Editor role assignment instead, it must cover all groups. |
| Collect group settings | `https://www.googleapis.com/auth/apps.groups.settings` | The Groups privilege (for example the Groups Admin or Groups Editor role), or super administrator. In accounts with several domains, use a delegated account on the primary domain. |
| Collect admin roles and privileges | `https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly` | The delegated account must be a **super administrator**. |

The first and last scopes are the same as for the `users` data stream, so they may already be delegated.

> NOTE: Google offers no read-only scope for group settings. `https://www.googleapis.com/auth/apps.groups.settings` allows **changing** the settings of any group the delegated account can manage. The integration only reads settings. Keep the delegated account's privileges as low as the table allows.

For Collect group settings, also enable the **Groups Settings API** in the service account's Google Cloud project, next to the Admin SDK API.

Add the scopes to the service account's domain-wide delegation as described in the Google Workspace Users section: **Edit** the existing client ID, keep the scopes already listed and use the exact scope strings. Scope changes can take up to 24 hours to take effect.

> NOTE: The integration requests all the scopes the data stream needs in one token request. If any of them is not delegated yet, Google issues no token and the **whole** `group_inventory` data stream stops, including the basic group inventory. Turn on an optional setting only after its scope is delegated and in effect. The other data streams of the integration, including `users`, are not affected.

The data stream calls `https://admin.googleapis.com` and, for group settings, `https://www.googleapis.com`. You can change them with the **Directory API Host** and **Groups Settings API Host** settings under the data stream's advanced options.

## Notes on the data

- Only **direct** members are read. A user who is a member through a nested group is not counted in this group's `member_counts`. Find the groups that contain a group by searching for its ID in `google_workspace.group_inventory.member_groups.id`.
- External members are found by email domain: a member is external when its email domain is not the domain of any group listed in the same cycle. A domain of your account that has no groups therefore looks external, and so do the other domains of your account when the **Domain** setting limits the listing to one domain.
- Admin roles that apply to the whole account add their privileges to `entity.attributes.permissions` but no ID to `entity.relationships.administers.entity.id`, because the group listing does not return the customer ID.
- Group owners in this data stream are the members with the Owner role. Administrators can manage every group without being listed as owners.
- Deleted groups are not included.

## Troubleshooting

- **The data stream stops with `oauth2: cannot fetch token` and the input health is Degraded.** Google rejected the token request. Check that every scope for the settings you enabled is delegated exactly as in the table above, and that enough time has passed for the change to take effect.
- **An error document reports an HTTP error on the groups request, no group documents are written and the input health is Degraded.** The group listing itself failed, so the cycle stopped. For HTTP 403, grant the delegated account Groups → Read with an assignment that has no condition. The next cycle starts again from the beginning.
- **A group document has `google_workspace.group_inventory.members_error`.** Its members could not be read, usually because the group was deleted during the cycle (HTTP 404). The other groups are not affected.
- **An error document reports HTTP 403 on a Groups Settings request, and group documents have `google_workspace.group_inventory.settings_error`.** Either the Groups Settings API is not enabled in the Google Cloud project, or the delegated account lacks the Groups privilege. Groups are still collected, without settings.
- **An error document reports HTTP 403 on a roles or role assignments request.** The delegated account is not a super administrator. Groups are still collected, without admin roles.
- **Fewer groups than expected.** The delegated account's Groups role assignment is probably limited by a condition, for example to security groups only. Use an assignment without a condition.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

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

### Users

This is the `users` dataset. It contains an inventory of user accounts, not events. See the Google Workspace Users section.

{{event "users"}}

{{fields "users"}}

### Group Inventory

This is the `group_inventory` dataset. It contains an inventory of Google groups, not events. See the Google Workspace Groups inventory section.

{{event "group_inventory"}}

{{fields "group_inventory"}}

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

### ChromeOS Devices

This is the `chromeos_devices` dataset. It contains an inventory of ChromeOS devices, not events. See the Google Workspace ChromeOS Devices section.

{{event "chromeos_devices"}}

{{fields "chromeos_devices"}}

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

### Gmail Reports

This is the `gmail_reports` dataset. It is collected from the Google Reports API and emits one document per event, so a single activity record containing several events produces several documents.

{{event "gmail_reports"}}

{{fields "gmail_reports"}}
### Gemini

This is the `gemini` dataset.

{{event "gemini"}}

{{fields "gemini"}}

### Gmail

This is the `gmail` dataset.

{{event "gmail"}}

{{fields "gmail"}}
