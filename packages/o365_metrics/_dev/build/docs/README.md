# Microsoft Office 365 Metrics Integration

This integration uses the [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview) and [Microsoft Management API](https://learn.microsoft.com/en-us/office/office-365-management-api/) to collect essential metrics from Microsoft Office 365, offering detailed insights into user activity, application usage, and overall system performance.

## Data streams

Following Microsoft 365 data can be collected by Microsoft Office 365 Metrics integration.

| Report          | API | Data-stream Name | Aggregation Level | Required permissions
|-----------------|-----|------------------|-------------------|--------------------|
| [Microsoft 365 Active Users Service User Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/active-users-ww?view=o365-worldwide)      |    [reportRoot: getOffice365ServicesUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365servicesusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Active Users metrics   |   `Period`-based   |   Reports.Read.All    |
| [Microsoft 365 Groups Activity Group Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/office-365-groups-ww?view=o365-worldwide)      |    [reportRoot: getOffice365GroupsActivityDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365groupsactivitydetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Groups Activity Group Detail   |   `Day`-based   |     Reports.Read.All    |
| [OneDrive Usage Account Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageAccountDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountdetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 OneDrive Usage Account Detail   |   `Day`-based   |     Reports.Read.All    |
| [OneDrive Usage Account Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageAccountCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountcounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 One Drive Usage metrics   |   `Period`-based   |    Reports.Read.All |
| [OneDrive Usage File Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageFileCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusagefilecounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 One Drive Usage metrics   |   `Period`-based   |     Reports.Read.All    |
| [OneDrive Usage Storage](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageStorage](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusagestorage?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 One Drive Usage metrics   |   `Period`-based   |       Reports.Read.All    |
| [Outlook Activity Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/email-activity-ww?view=o365-worldwide)      |    [reportRoot: getEmailActivityCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getemailactivitycounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Outlook Activity metrics   |   `Period`-based   |        Reports.Read.All    |
| [Outlook App Usage Version Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/email-apps-usage-ww?view=o365-worldwide)      |    [reportRoot: getEmailAppUsageVersionsUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getemailappusageversionsusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Outlook App Usage Version Counts metrics   |   `Period`-based   |     Reports.Read.All        |
| [Outlook Mailbox Usage Quota Status Mailbox Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/mailbox-usage?view=o365-worldwide)      |    [reportRoot: getMailboxUsageQuotaStatusMailboxCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagequotastatusmailboxcounts?view=graph-rest-1.0&tabs=http)    |  Microsoft 365 mailbox usage quota status metrics   |   `Period`-based   |   Reports.Read.All    |
| [Outlook Mailbox Usage Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/mailbox-usage?view=o365-worldwide)      |    [reportRoot: getMailboxUsageDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagedetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 mailbox usage detail metrics   |   `Period`-based   |     Reports.Read.All    |
| [SharePoint Site Usage Storage](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/sharepoint-site-usage-ww?view=o365-worldwide)      |    [reportRoot: getSharePointSiteUsageStorage](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagestorage?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Sharepoint Site Usage metrics   |   `Period`-based   |    Reports.Read.All    |
| [SharePoint Site Usage Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/sharepoint-site-usage-ww?view=o365-worldwide)      |    [reportRoot: getSharePointSiteUsageDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Sharepoint Site Usage metrics   |   `Period`-based   |       Reports.Read.All    |
| [Teams Device Usage User Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-device-usage-preview?view=o365-worldwide)      |    [reportRoot: getTeamsDeviceUsageUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsdeviceusageusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Teams Device Usage User Counts metrics   |   `Period`-based   |      Reports.Read.All    |
| [Teams User Activity User Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide)      |    [reportRoot: getTeamsUserActivityUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Teams User Activity User Counts metrics   |   `Period`-based   |     Reports.Read.All    |
| [Teams User Activity User Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide)      |    [reportRoot: getTeamsUserActivityUserDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityuserdetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Teams User Activity User Detail   |    `Day`-based   |       Reports.Read.All    |
| [Viva Engage Groups Activity Group Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/viva-engage-groups-activity-report-ww?view=o365-worldwide)      |    [reportRoot: getYammerGroupsActivityDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammergroupsactivitydetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Viva Engage Groups Activity   |   `Day`-based   |     Reports.Read.All    |
| [Viva Engage Device Usage User Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/viva-engage-device-usage-report-ww?view=o365-worldwide)      |    [reportRoot: getYammerDeviceUsageUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammerdeviceusageusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Viva Engage Device Usage User Counts metrics   |   `Period`-based   |      Reports.Read.All    |
| [Service Health](https://learn.microsoft.com/en-us/graph/service-communications-concept-overview?view=o365-worldwide)                                                 |    [reportRoot: getServiceHealth](https://learn.microsoft.com/en-us/graph/api/servicehealth-get?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Service Health metrics   |   No aggregation  |    ServiceHealth.Read.All  |
| [Subscriptions](https://learn.microsoft.com/en-us/graph/api/resources/subscribedsku?view=graph-rest-1.0?view=o365-worldwide)                                                 |    [subscribedSkus](https://learn.microsoft.com/en-us/graph/api/resources/subscribedsku?view=graph-rest-1.0), [subscriptions](https://learn.microsoft.com/en-us/graph/api/resources/companysubscription?view=graph-rest-1.0)   |   Microsoft 365 Subscriptions metrics   |   No aggregation  | LicenseAssignment.Read.All  |
| [Teamms Call Quality](https://learn.microsoft.com/en-us/graph/api/resources/communications-api-overview?view=graph-rest-1.0?view=o365-worldwide)                                                 |    [reportRoot: callRecords](https://learn.microsoft.com/en-us/graph/api/callrecords-callrecord-list-sessions?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Teams Call Quality metrics   |   No aggregation  |   CallRecords.Read.All    |
| Tenant Settings | [organization](https://learn.microsoft.com/en-us/graph/api/resources/organization?view=graph-rest-1.0), [adminReportSettings](https://learn.microsoft.com/en-us/graph/api/resources/adminreportsettings?view=graph-rest-1.0) | Microsoft 365 Tenant Settings | No aggregation | Organization.Read.All, ReportSettings.Read.All, Directory.Read.All  |
| [App Registrations](https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0) |    [List Applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 App Registrations   |   No aggregation  | Application.Read.All, User.Read(delegated) |
| [Entra Features](https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0&tabs=http) |    [Organization](https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0&tabs=http), [PremisesSync](https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization)    |   Microsoft 365 Entra Connect  |   No aggregation  | Organization.Read.All, User.Read(delegated) |
| Entra ID users | [user](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0), [riskDetection](https://learn.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0) | Microsoft 365 Entra Connect User metrics | No aggregation | User.Read.All, IdentityRiskEvent.Read.All
| Entra Agent | [agent](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-aadc-admin-agent) | Microsoft 365 Entra Agent metrics | No aggregation | RBAC role
| Entra Alerts |  [alerts](https://learn.microsoft.com/en-us/entra/permissions-management/ui-triggers) | Microsoft 365 Entra Alerts metrics | No aggregation | RBAC role


## Setup

To use this package you need to enable datastreams you want to collect metrics for and register an application in [Microsoft Entra ID (formerly known as Azure Active Directory)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id).

Once the application is registered, configure and/or note the following to setup O365 metrics Elastic integration:
1. Note `Application (client) ID` and the `Directory (tenant) ID` in the registered application's `Overview` page.
2. Create a new secret to configure the authentication of your application. 
    - Navigate to `Certificates & Secrets` section.
    - Click `New client secret` and provide some description to create new secret.
    - Note the `Value` which is required for the integration setup.
3. Add permissions to your registered application.
    - Select and add the appropriate permissions from the available tiles.
    - For this package, we primarily use Graph APIs, so you can choose `Microsoft Graph`, which will display the Delegated and Application permission sections.
    - Refer to the `Required Permissions` column in the table under [Data streams](#data-streams) section to identify the permissions required for each data stream and select accordingly. You can also refer to the Permissions section in the API documentation for each data stream to determine the necessary permissions.
    - Ensure Reports.Read.All from Microsoft Graph is added, as most APIs are report-based.
    - After the permissions are added, the admin will need to grant consent for a few permissions.

Once the secret is created and permissions are granted by admin, setup Elastic Agent's Microsoft O365 integration:
- Click `Add Microsoft Office 365`.
- Enable `Collect Office 365 metrics via Graph API using CEL Input`.
- Add `Directory (tenant) ID` noted in Step 1 into `Directory (tenant) ID` parameter. This is required field.
- Add `Application (client) ID` noted in Step 1 into `Application (client) ID` parameter. This is required field.
- Add the secret `Value` noted in Step 2 into `Client Secret` parameter. This is required field.
- Oauth2 Token URL can be added to generate the tokens during the oauth2 flow. If not provided, above `Directory (tenant) ID` will be used for oauth2 token generation.
- Modify any other parameters as necessary.

### Period-based vs Day-based data-streams

Some data-streams listed earlier ingest data aggregated by a `period`, while other data-streams ingest data aggregated by `day` i.e., aggregated daily.

- When configuring `Period-based` data-streams, the configuration option `Period` must be used during setup. The supported values are: D7, D30, D90, and D180.
- As `Day-based` data-streams ingest aggregated data per day, the configuration option `Initial Interval` must be set which indicates how far back (in number of days) to fetch the data. Values between 1-28 are allowed.

### Additional Information on Day-based data-streams

Microsoft 365 reports are typically available within [48 hours](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/activity-reports?view=o365-worldwide), but may sometimes take several days. As per their [documentation](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide#interpret-the-microsoft-teams-user-activity-report), data quality is ensured by performing daily validation checks to fill any gaps in data. During this process, users may notice differences in historical data in Microsoft 365 Reports in admin center.

To ensure these filled gaps and historical data-accuracy is also ingested into Elastic, the Microsoft Office 365 Metrics integration enables you to adjust `Sync Days in the past` parameter for `Day-based` data-streams. You can use this parameter to re-fetch the Microsoft 365 reports starting from *N* days in the past. Default value for this paramater is `3`. You can gradually increase this value if you see any discrepancies between Microsoft Reports and Elastic data (maximum value allowed is `28`).

Due to this re-fetching of data on same dates and the way Elastic data-streams work in [append-only](https://www.elastic.co/guide/en/elasticsearch/reference/current/data-streams.html) design, the ingested data may have duplicates. For example, you may see duplicate documents in Elastic on the source data-stream backed indices per resource (user/group/site) per report date. To maintain only the latest copy of document, the Microsoft Office 365 Metrics integration installs [Latest Transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-overview.html#latest-transform-overview), one per report. These latest transform periodically pulls the data from source data-stream backed indices into a destination non-data-stream backed index. Hence the destination indices only contains single (latest) document per resource (user/group/site) per report date. Inside the reports dataset, you can distinguish between source and destination indices using the field `labels.is_transform_source`. This is set to `true` for source data-stream backed indices and `false` for destination (latest) indices.

Thus when searching for data, you should use a filter `labels.is_transform_source: false` to avoid seeing any duplicates. The Microsoft Office 365 Metrics integration dashboards also has this filter to only show the latest datapoints.

As the latest data is available in destination indices, the source data-stream backed indices are purged based on ILM policy `metrics-o365_metrics.<data_stream>-default_policy`.

| o365.metrics.report.name          | Source filter | Source indices | Destination filter | Destination indices | Destination alias |
|------------------|:-------:|:-------:|:-------:|:-------:|:-------:|
| Microsoft 365 Groups Activity Group Detail  |  `labels.is_transform_source: true`  | `metrics-o365_metrics.groups_activity_group_detail-*` |  `labels.is_transform_source: false`  | `metrics-o365_metrics.groups_activity_group_detail_latest-*` | `metrics-o365_metrics.groups_activity_group_detail_latest` |
| OneDrive Usage Account Detail  |  `labels.is_transform_source: true`  | `metrics-o365_metrics.onedrive_usage_account_detail-*` |  `labels.is_transform_source: false`  | `metrics-o365_metrics.onedrive_usage_account_detail_latest-*` | `metrics-o365_metrics.onedrive_usage_account_detail_latest` |
| Teams User Activity User Detail  |  `labels.is_transform_source: true`  | `metrics-o365_metrics.teams_user_activity_user_detail-*` |  `labels.is_transform_source: false`  | `metrics-o365_metrics.teams_user_activity_user_detail_latest-*` | `metrics-o365_metrics.teams_user_activity_user_detail_latest` |
| Viva Engage Groups Activity Group Detail  |  `labels.is_transform_source: true`  | `metrics-o365_metrics.viva_engage_groups_activity_group_detail-*` |  `labels.is_transform_source: false`  | `metrics-o365_metrics.viva_engage_groups_activity_group_detail_latest-*` | `metrics-o365_metrics.viva_engage_groups_activity_group_detail_latest` |

**Note:** `Sync Days in the past` and `Latest Transforms` are only used in `Day`-based data-streams, i.e., for data-streams aggregated per day.

### Data Anonymization

By default for all Microsoft 365 usage reports, the user names, emails, group, or site information are anonymized by Microsoft using MD5 hashes. You can revert this change for a tenant and show identifiable user, group, and site information if your organization's privacy practices allow it. To do this, follow below steps:
1. Login to [Microsoft 365 admin center](https://admin.microsoft.com/)
2. Navigate to `Settings` --> `Org Settings` --> `Services` page.
3. Select `Reports`
4. Uncheck the statement `Display concealed user, group, and site names in all reports`, and then save your changes.

## Metrics

Uses the Microsoft 365 Graph API to retrieve metrics from Microsoft 365.

### Active Users Services User Count

Get details about Active Users Services User Count from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365servicesusercounts?view=graph-rest-1.0&tabs=http).

{{event "active_users_services_user_counts"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "active_users_services_user_counts"}}

### Entra ID users

Get details about users in Microsoft Entra ID.

{{ event "entra_id_users" }}

{{ fields "entra_id_users" }}

### Mailbox Usage Quota Status

Get details about Mailbox Usage Quota Status from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagequotastatusmailboxcounts?view=graph-rest-1.0&tabs=http).

{{event "mailbox_usage_quota_status"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "mailbox_usage_quota_status"}}

### Mailbox Usage Detail

Get details about Mailbox Usage Detail from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagedetail?view=graph-rest-1.0&tabs=http).

{{event "mailbox_usage_detail"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "mailbox_usage_detail"}}

### Microsoft 365 Groups Activity Group Detail

Get details about Microsoft 365 groups activity by group from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365groupsactivitydetail?view=graph-rest-1.0&tabs=http).

{{event "groups_activity_group_detail"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "groups_activity_group_detail"}}

### OneDrive Usage Account Detail

Get details about OneDrive usage by account from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountdetail?view=graph-rest-1.0&tabs=http).

{{event "onedrive_usage_account_detail"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "onedrive_usage_account_detail"}}

### OneDrive Usage Account Counts

Get details about OneDrive usage by account counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountcounts?view=graph-rest-1.0&tabs=http).

{{event "onedrive_usage_account_counts"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "onedrive_usage_account_counts"}}

### OneDrive Usage File Counts

Get details about OneDrive usage by file counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusagefilecounts?view=graph-rest-1.0&tabs=http).

{{event "onedrive_usage_file_counts"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "onedrive_usage_file_counts"}}

### OneDrive Usage Storage

Get details about OneDrive usage by storage from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusagestorage?view=graph-rest-1.0&tabs=http).

{{event "onedrive_usage_storage"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "onedrive_usage_storage"}}

### Outlook Activity

Get details about Outlook Activity from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getemailactivitycounts?view=graph-rest-1.0&tabs=http).

{{event "outlook_activity"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "outlook_activity"}}

### Outlook App Usage Version Counts

Get details about Microsoft Outlook App Usage Version Counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getemailappusageversionsusercounts?view=graph-rest-1.0&tabs=http).

{{event "outlook_app_usage_version_counts"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "outlook_app_usage_version_counts"}}

### SharePoint Site Usage Detail

Get details about SharePoint Site Usage Detail from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-1.0&tabs=http).

{{event "sharepoint_site_usage_detail"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "sharepoint_site_usage_detail"}}

### SharePoint Site Usage Storage

Get details about SharePoint Site Usage Storage from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagestorage?view=graph-rest-1.0&tabs=http).

{{event "sharepoint_site_usage_storage"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "sharepoint_site_usage_storage"}}

### Teams User Activity User Counts

Get details about Teams User Activity User Counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityusercounts?view=graph-rest-1.0&tabs=http).

{{event "teams_user_activity_user_counts"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "teams_user_activity_user_counts"}}

### Teams User Activity User Detail

Get details about Teams User Activity User Detail from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityuserdetail?view=graph-rest-1.0&tabs=http).

{{event "teams_user_activity_user_detail"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "teams_user_activity_user_detail"}}

### Viva Engage Groups Activity Group Detail

Get details about Yammer Groups Activity Group Detail by group from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammergroupsactivitydetail?view=graph-rest-1.0&tabs=http).

{{event "viva_engage_groups_activity_group_detail"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "viva_engage_groups_activity_group_detail"}}

### Viva Engage Device Usage User Counts

Get details about Yammer Device Usage User Counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammerdeviceusageusercounts?view=graph-rest-1.0&tabs=http).

{{event "viva_engage_device_usage_user_counts"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "viva_engage_device_usage_user_counts"}}


### Teams Device Usage User Counts

Get details about Teams Device Usage User Counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsdeviceusageusercounts?view=graph-rest-1.0&tabs=http).

{{event "teams_device_usage_user_counts"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "teams_device_usage_user_counts"}}

### Service Health

Get details about Service Health from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/servicehealth-get?view=graph-rest-1.0&tabs=http).

{{event "service_health"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "service_health"}}


### Subscriptions

Get details about Subscriptions from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0&tabs=http).

{{event "subscriptions"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "subscriptions"}}


### Teams Call Quality

Get details about Teams Call Quality from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/callrecords-callrecord-list-sessions?view=graph-rest-1.0&tabs=http).

{{event "teams_call_quality"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "teams_call_quality"}}

### Tenant Settings

Get details about tenant settings in Microsoft Entra ID.

{{event "tenant_settings"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "tenant_settings"}}

### App Registrations

Get details about apps registered in Microsoft Entra ID. [Microsoft API](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http).

{{event "app_registrations"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "app_registrations"}}

### Entra Features

Get details about Entra Features. [Microsoft API](https://learn.microsoft.com/en-us/graph/api/resources/organization?view=graph-rest-1.0).

{{event "entra_features"}}

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "entra_features"}}

### Entra Agent

Get details about Entra Agent. [Microsoft Docs](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-install).

{{event "entra_agent"}}

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "entra_agent"}}

### Entra Alerts

Get details about Entra Alerts. [Microsoft Docs](https://learn.microsoft.com/en-us/azure/container-apps/alerts).

{{event "entra_alerts"}}

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "entra_alerts"}}
