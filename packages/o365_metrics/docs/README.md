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

### Active Users

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
| o365metrics.activeusers.ExchangeActive | Number of Exchange active users. | integer |
| o365metrics.activeusers.ExchangeInactive | Number of Exchange inactive users. | integer |
| o365metrics.activeusers.Office365Active | Number of Office 365 active users. | integer |
| o365metrics.activeusers.Office365Inactive | Number of Office 365 inactive users. | integer |
| o365metrics.activeusers.OneDriveActive | Number of OneDrive active users. | integer |
| o365metrics.activeusers.OneDriveInactive | Number of OneDrive inactive users. | integer |
| o365metrics.activeusers.ReportPeriod | Report period in days. | integer |
| o365metrics.activeusers.ReportRefreshDate | Date when the report was refreshed. | date |
| o365metrics.activeusers.SharePointActive | Number of SharePoint active users. | integer |
| o365metrics.activeusers.SharePointInactive | Number of SharePoint inactive users. | integer |
| o365metrics.activeusers.SkypeForBusinessActive | Number of Skype for Business active users. | integer |
| o365metrics.activeusers.SkypeForBusinessInactive | Number of Skype for Business inactive users. | integer |
| o365metrics.activeusers.TeamsActive | Number of Teams active users. | integer |
| o365metrics.activeusers.TeamsInactive | Number of Teams inactive users. | integer |
| o365metrics.activeusers.YammerActive | Number of Yammer active users. | integer |
| o365metrics.activeusers.YammerInactive | Number of Yammer inactive users. | integer |

