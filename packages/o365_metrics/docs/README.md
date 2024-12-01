# Microsoft Office 365 Metrics Integration

This integration is to collect metrics for [Microsoft Office 365](https://learn.microsoft.com/en-us/graph/overview).

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

### One Drive Usage Account Counts

Uses the Office 365 Management Graph API to retrieve metrics from Office 365. 


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
| input.type | Type of Filebeat input. | keyword |
| o365metrics.onedrive_usageaccountcounts.Active | The number of OneDrive accounts that were active during the reporting period. | integer |
| o365metrics.onedrive_usageaccountcounts.ReportDate | The date the OneDrive account usage report was generated. | date |
| o365metrics.onedrive_usageaccountcounts.ReportPeriod | The duration of the reporting period for OneDrive account activity, in days. | integer |
| o365metrics.onedrive_usageaccountcounts.ReportRefreshDate | The date when the OneDrive account usage data was last refreshed. | date |
| o365metrics.onedrive_usageaccountcounts.SiteType | The type of OneDrive sites included in the report (e.g., All, Team, Personal). | keyword |
| o365metrics.onedrive_usageaccountcounts.Total | The total number of OneDrive accounts evaluated in the report. | integer |


### One Drive Usage Storage

Uses the Office 365 Management Graph API to retrieve metrics from Office 365. 


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
| input.type | Type of Filebeat input. | keyword |
| o365metrics.onedrive_usagestorage.ReportDate | The date the OneDrive storage usage report was generated. | date |
| o365metrics.onedrive_usagestorage.ReportPeriod | The duration of the reporting period for OneDrive storage usage, in days. | integer |
| o365metrics.onedrive_usagestorage.ReportRefreshDate | The date when the OneDrive storage usage data was last refreshed. | date |
| o365metrics.onedrive_usagestorage.SiteType | The type of OneDrive sites included in the report (e.g., All, Team, Personal). | keyword |
| o365metrics.onedrive_usagestorage.StorageUsedByte | The total storage used across OneDrive accounts during the reporting period, in bytes. | integer |



### One Drive Usage File Counts

Uses the Office 365 Management Graph API to retrieve metrics from Office 365. 


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
| input.type | Type of Filebeat input. | keyword |
| o365metrics.onedrive_usagefilecounts.Active | The number of OneDrive accounts with active file usage during the reporting period. | integer |
| o365metrics.onedrive_usagefilecounts.ReportDate | The date the report was generated. | date |
| o365metrics.onedrive_usagefilecounts.ReportPeriod | The duration of the reporting period, in days. | integer |
| o365metrics.onedrive_usagefilecounts.ReportRefreshDate | The date when the data in the report was last refreshed. | date |
| o365metrics.onedrive_usagefilecounts.SiteType | The type of sites included in the OneDrive usage report (e.g., All). | keyword |
| o365metrics.onedrive_usagefilecounts.Total | The total number of OneDrive accounts included in the report. | integer |

