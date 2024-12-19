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
    - If `User.Read` and `Reports.Read.All` permission under `Microsoft.Graph` tile is not added by default, add this permission.
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

Uses the Office 365 Graph API to retrieve metrics from Office 365.

### MailboxUsage

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
| o365.metrics.mailbox.quota.status.indeterminate.count | The number of mailboxes where the quota status could not be determined. | integer |
| o365.metrics.mailbox.quota.status.report.date | The specific date for which the report data applies. | date |
| o365.metrics.mailbox.quota.status.report.period | The duration (e.g., 7 days) over which the quota status data is aggregated. | integer |
| o365.metrics.mailbox.quota.status.report.refresh_date | The date when the report data was last updated. | date |
| o365.metrics.mailbox.quota.status.send/receive_prohibited.count | The number of mailboxes restricted from both sending and receiving emails due to exceeding their total quota during the reporting period. | integer |
| o365.metrics.mailbox.quota.status.send_prohibited.count | The number of mailboxes restricted from sending emails due to exceeding their send quota during the reporting period. | integer |
| o365.metrics.mailbox.quota.status.under_limit.count | The number of mailboxes operating within their assigned quota limits during the reporting period. | integer |
| o365.metrics.mailbox.quota.status.warning_issued.count | The number of mailboxes that have exceeded their warning threshold quota during the reporting period. | integer |
| o365.metrics.mailbox.usage.detail.deleted_item.count | The number of items in the deleted items folder. | integer |
| o365.metrics.mailbox.usage.detail.deleted_item_quota.byte | The quota limit for the deleted items folder (in bytes). | integer |
| o365.metrics.mailbox.usage.detail.deleted_item_size.byte | The total size of items in the deleted items folder (in bytes). | integer |
| o365.metrics.mailbox.usage.detail.issue_warning_quota.byte | The mailbox size limit at which a warning is issued (in bytes). | integer |
| o365.metrics.mailbox.usage.detail.item.count | The total number of items in the mailbox. | integer |
| o365.metrics.mailbox.usage.detail.prohibit_send/receive_quota.byte | The mailbox size limit at which sending and receiving messages is prohibited (in bytes). | integer |
| o365.metrics.mailbox.usage.detail.prohibit_send_quota.byte | The mailbox size limit at which sending messages is prohibited (in bytes). | integer |
| o365.metrics.mailbox.usage.detail.report.period | The reporting period over which the data is aggregated (in days). | integer |
| o365.metrics.mailbox.usage.detail.report.refresh_date | The date when the report data was last updated. | date |
| o365.metrics.mailbox.usage.detail.storage_used.byte | The total storage used in the mailbox (in bytes). | integer |


### One Drive Usage

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
| o365.metrics.onedrive.usage.account.counts.active.count | The number of OneDrive accounts that were active during the reporting period. | integer |
| o365.metrics.onedrive.usage.account.counts.report.date | The date the report was generated. | date |
| o365.metrics.onedrive.usage.account.counts.report.period | The duration of the reporting period, in days. | integer |
| o365.metrics.onedrive.usage.account.counts.report.refresh_date | The date when the data in the report was last refreshed. | date |
| o365.metrics.onedrive.usage.account.counts.total.count | The total number of OneDrive accounts evaluated in the report. | integer |
| o365.metrics.onedrive.usage.file.counts.active.count | The number of OneDrive accounts with active file usage during the reporting period. | integer |
| o365.metrics.onedrive.usage.file.counts.report.date | The date the report was generated. | date |
| o365.metrics.onedrive.usage.file.counts.report.period | The duration of the reporting period, in days. | integer |
| o365.metrics.onedrive.usage.file.counts.report.refresh_date | The date when the data in the report was last refreshed. | date |
| o365.metrics.onedrive.usage.file.counts.total.count | The total number of OneDrive accounts evaluated in the report. | integer |
| o365.metrics.onedrive.usage.storage.report.date | The date the report was generated. | date |
| o365.metrics.onedrive.usage.storage.report.period | The duration of the reporting period, in days. | integer |
| o365.metrics.onedrive.usage.storage.report.refresh_date | The date when the data in the report was last refreshed. | date |
| o365.metrics.onedrive.usage.storage.used_byte | The total storage used across OneDrive accounts during the reporting period, in bytes. | integer |


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


### OutlookAppUsage

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
| o365.metrics.outlook.app.usage.outlook_2007.count | The count of unique users using Outlook 2007 during the reporting period. | integer |
| o365.metrics.outlook.app.usage.outlook_2010.count | The count of unique users using Outlook 2010 during the reporting period. | integer |
| o365.metrics.outlook.app.usage.outlook_2013.count | The count of unique users using Outlook 2013 during the reporting period. | integer |
| o365.metrics.outlook.app.usage.outlook_2016.count | The count of unique users using Outlook 2016 during the reporting period. | integer |
| o365.metrics.outlook.app.usage.outlook_2019.count | The count of unique users using Outlook 2019 during the reporting period. | integer |
| o365.metrics.outlook.app.usage.outlook_m365.count | The count of unique users using the Outlook Microsoft 365 version during the reporting period. | integer |
| o365.metrics.outlook.app.usage.report.period | The duration (e.g., 7 days) over which the report data is aggregated. | integer |
| o365.metrics.outlook.app.usage.report.refresh_date | The date when the report data was last updated. | date |
| o365.metrics.outlook.app.usage.undetermined.count | The count of unique users whose Outlook version could not be identified. | integer |

