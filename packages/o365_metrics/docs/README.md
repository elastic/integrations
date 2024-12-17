# Microsoft Office 365 Metrics Integration

This integration uses the [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview) to collect essential metrics from Microsoft Office 365, offering detailed insights into user activity, application usage, and overall system performance.

## Setup

To use this package you need to enable datastreams you want to collect metrics for and register an application in [Microsoft Entra ID (formerly known as Azure Active Directory)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id).

Once the application is registered, configure and/or note the following to setup O365 metrics Elastic integration:
1. Note `Application (client) ID` and the `Directory (tenant) ID` in the registered application's `Overview` page.
2. Create a new secret to configure the authentication of your application. 
    - Navigate to `Certificates & Secrets` section.
    - Click `New client secret` and provide some description to create new secret.
    - Note the `Value` which is required for the integration setup.
3. Add permissions to your registered application. Please check [O365 Graph API permissions](https://learn.microsoft.com/en-us/graph/reportroot-authorization) for more details.
    - Navigate to `API permissions` page and click `Add a permission`
    - Select `Office 365 Management APIs` tile from the listed tiles.
    - Click `Application permissions`.
    - If `User.Read` permission under `Microsoft.Graph` tile is not added by default, add this permission.
    - After the permissions are added, the admin has to grant consent for these permissions.

Once the secret is created and permissions are granted by admin, setup Elastic Agent's Microsoft O365 integration:
- Click `Add Microsoft Office 365`.
- Enable `Collect Office 365 metrics via Graph API using CEL Input`.
- Add `Directory (tenant) ID` noted in Step 1 into `Directory (tenant) ID` parameter. This is required field.
- Add `Application (client) ID` noted in Step 1 into `Application (client) ID` parameter. This is required field.
- Add the secret `Value` noted in Step 2 into `Client Secret` parameter. This is required field.
- Oauth2 Token URL can be added to generate the tokens during the oauth2 flow. If not provided, above `Directory (tenant) ID` will be used for oauth2 token generation.
- Modify any other parameters as necessary.



## Compatibility



## Metrics

Uses the Office 365 Management Graph API to retrieve metrics from Office 365.

### OutlookActivity
**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| o365.metrics.outlook.activity.emails_read.count | The count of email messages read by users during the reporting period. | integer |
| o365.metrics.outlook.activity.emails_received.count | The count of email messages received by users during the reporting period. | integer |
| o365.metrics.outlook.activity.emails_sent.count | The count of email messages sent by users during the reporting period. | integer |
| o365.metrics.outlook.activity.meeting_created.count | The count of calendar meetings created by users during the reporting period. | integer |
| o365.metrics.outlook.activity.meeting_interacted.count | The count of meetings where users interacted (e.g., accepted, declined, or modified) during the reporting period. | integer |
| o365.metrics.outlook.activity.report_date | The specific date for which the report data applies. | date |
| o365.metrics.outlook.activity.report_period | The duration (e.g., 7 days) over which the quota status data is aggregated. | integer |
| o365.metrics.outlook.activity.report_refresh_date | The date when the report data was last updated. | date |


### Active Users
**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| o365.metrics.active_users.exchange_active | Number of Exchange active users. | integer |
| o365.metrics.active_users.exchange_inactive | Number of Exchange inactive users. | integer |
| o365.metrics.active_users.office_365_active | Number of Office 365 active users. | integer |
| o365.metrics.active_users.office_365_inactive | Number of Office 365 inactive users. | integer |
| o365.metrics.active_users.onedrive_active | Number of OneDrive active users. | integer |
| o365.metrics.active_users.onedrive_inactive | Number of OneDrive inactive users. | integer |
| o365.metrics.active_users.report_period | Report period in days. | integer |
| o365.metrics.active_users.report_refresh_date | Date when the report was refreshed. | date |
| o365.metrics.active_users.sharepoint_active | Number of SharePoint active users. | integer |
| o365.metrics.active_users.sharepoint_inactive | Number of SharePoint inactive users. | integer |
| o365.metrics.active_users.skype_for_business_active | Number of Skype for Business active users. | integer |
| o365.metrics.active_users.skype_for_business_inactive | Number of Skype for Business inactive users. | integer |
| o365.metrics.active_users.teams_active | Number of Teams active users. | integer |
| o365.metrics.active_users.teams_inactive | Number of Teams inactive users. | integer |
| o365.metrics.active_users.yammer_active | Number of Yammer active users. | integer |
| o365.metrics.active_users.yammer_inactive | Number of Yammer inactive users. | integer |
