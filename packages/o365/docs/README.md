# Microsoft Office 365 Integration

This integration is for [Microsoft 365](https://www.microsoft.com/en-in/microsoft-365/). You can use this integration to retrieve information about user, admin, system, and policy actions and events from Microsoft 365 and Azure AD activity logs using [Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference). You can also ingest several Microsoft 365 usage reports using [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/resources/reportroot?view=graph-rest-1.0).

## Data streams

The Microsoft Office 365 integration collects 1 type of `logs` and 1 type of `metrics`.

### Audit Logs

Audit Logs provided by Office 365 Management Activity API aggregates actions and events into tenant-specific content blobs. This includes events of all Office 365 customers' and partners' management tasks, including security, compliance, reporting, and auditing. This data is ingested into `logs` datatype and can be viewed under `logs-*` dataview.

The following content types are supported:
- Audit.AzureActiveDirectory
- Audit.Exchange
- Audit.SharePoint
- Audit.General (includes all other workloads not included in the previous content types)
- DLP.All (DLP events only for all workloads)

### Usage Reports

Microsoft 365 usage reports collected using Microsoft Graph API give you insight into the how people in your business are using Microsoft 365 services. This data is ingested into `metrics` datatype and can be viewed under `metrics-*` dataview.

#### Usage Reports Available

Following Microsoft 365 usage reports can be collected by Microsoft Office 365 integration.

| Report          | API | 
|------------------|:-------:|
| [Microsoft Teams User Activity User Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide)      |    [reportRoot: getTeamsUserActivityUserDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityuserdetail?view=graph-rest-1.0&tabs=http)    |
| [Office365 Groups Activity Group Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/office-365-groups-ww?view=o365-worldwide)      |    [reportRoot: getOffice365GroupsActivityDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365groupsactivitydetail?view=graph-rest-1.0&tabs=http)    |
| [OneDrive Usage Account Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageAccountDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountdetail?view=graph-rest-1.0&tabs=http)    |
| [SharePoint Site Usage Site Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/sharepoint-site-usage-ww?view=o365-worldwide)      |    [reportRoot: getSharePointSiteUsageDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-1.0&tabs=http)    |
| [Viva Engage Groups Activity Group Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/viva-engage-groups-activity-report-ww?view=o365-worldwide)      |    [reportRoot: getYammerGroupsActivityDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammergroupsactivitydetail?view=graph-rest-1.0&tabs=http)    |


#### Data Setup in Usage Reports

All the reports are under one generic dataset which can be queried as `data_stream.dataset: o365.reports`. The reports are distingushed from one another using the field `o365.reports.metadata.name`.

Microsoft 365 reports are typically available within [48 hours](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/activity-reports?view=o365-worldwide), but may sometimes take several days. As per their [documentation](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide#interpret-the-microsoft-teams-user-activity-report), data quality is ensured by performing daily validation checks to fill any gaps in data. 

To ensure these filled gaps from the reports are also ingested into Elastic, the Microsoft Office 365 integration enables you to adjust `Sync Days in the past` parameter when configuring the integration. You can use this parameter to re-fetch the Microsoft 365 reports starting from *N* days in the past. Default value for this paramater is `3`. You can gradually increase this value (maximum allowed is `29`) if you see any discrepancies between Microsoft Reports and Elastic data.

Due to this re-fetching of data on same dates and the way Elastic data-streams work in [append-only](https://www.elastic.co/guide/en/elasticsearch/reference/current/data-streams.html) design, the ingested data may have duplicates. For example, you may see duplicate documents in Elastic on the source data-stream backed indices per resource (user/group/site) per report date. To maintain only the latest copy of document, the Microsoft Office 365 integration installs [Latest Transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-overview.html#latest-transform-overview), one per report type. These latest transform periodically pulls the data from source data-stream backed indices into a destination non-data-stream backed index. Hence the destination indices only contains single (latest) document per resource (user/group/site) per report date. Inside the reports dataset, you can distinguish between source and destination indices using the field `labels.is_transform_source`. This is set to `true` for source data-stream backed indices and `false` for destination (latest) indices.

Thus when searching for data, you should use a filter `labels.is_transform_source: false` to avoid seeing any duplicates. The Microsoft Office 365 dashboards also has this filter to only show the latest datapoints.

As the latest data is available in destination indices, the source data-stream backed indices are purged based on ILM policy `metrics-o365.reports-default_policy`.

| o365.reports.metadata.name          | Source filter | Source indices | Destination filter | Destination indices | Destination alias |
|------------------|:-------:|:-------:|:-------:|:-------:|:-------:|
| Microsoft Teams User Activity User Detail  |  `labels.is_transform_source: true`  | `.ds-metrics-o365.reports-*` |  `labels.is_transform_source: false`  | `metrics-o365_latest.teams_user_activity_user-*` | `metrics-o365_latest.teams_user_activity_user` |
| Office365 Groups Activity Group Detail  |  `labels.is_transform_source: true`  | `.ds-metrics-o365.reports-*` |  `labels.is_transform_source: false`  | `metrics-o365_latest.office365_groups_activity_group-*` | `metrics-o365_latest.office365_groups_activity_group` |
| OneDrive Usage Account Detail  |  `labels.is_transform_source: true`  | `.ds-metrics-o365.reports-*` |  `labels.is_transform_source: false`  | `metrics-o365_latest.onedrive_usage_account-*` | `metrics-o365_latest.onedrive_usage_account` |
| SharePoint Site Usage Site Detail  |  `labels.is_transform_source: true`  | `.ds-metrics-o365.reports-*` |  `labels.is_transform_source: false`  | `metrics-o365_latest.sharepoint_site_usage_site-*` | `metrics-o365_latest.sharepoint_site_usage_site` |
| Viva Engage Groups Activity Group Detail  |  `labels.is_transform_source: true`  | `.ds-metrics-o365.reports-*` |  `labels.is_transform_source: false`  | `metrics-o365_latest.viva_engage_groups_activity_group-*` | `metrics-o365_latest.viva_engage_groups_activity_group` |

To view the latest transforms after installation, navigate to `Management` --> `Stack Management` --> `Transforms` in Kibana.

## Requirements

### Installing and managing an Elastic Agent

You need to have Elastic Agent installed. For detailed guidance, refer to the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). There are several options for installing and managing Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended)

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users)

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Before installing the Elastic Agent, check the [minimum requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Permissions

Each data stream collects different kinds of logs or metric data, which may require dedicated permissions.

#### Audit Logs

To retrieve audit logs using the Office 365 Management Activity API, you need `ActivityFeed.Read` and `ActivityFeed.ReadDlp` permissions on your Azure registered application. For detailed instructions on how to register an Azure application and setup permissions and secret, see [setup](#setup) below.

You also need to [enable `Audit Log`](https://learn.microsoft.com/en-us/purview/audit-log-enable-disable).

#### Usage Reports

To retrieve Microsoft 365 usage report metrics using the Microsoft Graph API, you need `Reports.Read.All` permission on your Azure registered application. For detailed instructions on how to register an Azure application and setup permissions and secret, see [setup](#setup) below.

## Setup

### Register application in Microsoft Entra ID

To use this integration you need to register an application in [Microsoft Entra ID (formerly known as Azure Active Directory)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id). You can register the application in Microsoft Entra ID using Azure Portal or Microsoft Entra admin center. To register your app in Microsoft Entra ID, you need a subscription to Office 365 and a subscription to Azure that has been associated with your Office 365 subscription.

#### Register application using Azure Portal

1. Login to [Azure Portal](https://portal.azure.com).
2. Under `Azure services`, select `Microsoft Entra ID`.
3. Under `Manage`, select `App registrations`.
4. Click on `New Registration` and enter a `Name` for your application. This registers your application.

For more details see [use-the-azure-portal-to-register-your-application](https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis#use-the-azure-portal-to-register-your-application-in-microsoft-entra-id)

#### Register application using Microsoft Entra admin center 

1. Login to [Microsoft Entra Admin Center](https://entra.microsoft.com).
2. Under `Identity`, navigate to `Applications` and select `App registrations`.
3. Click on `New Registration` and enter a `Name` for your application. This registers your application.

For more details see [quickstart-register-app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate)

### Create Secret for registered application

Create a new secret to configure the authentication of your application. Inside your application:
1. Navigate to `Certificates & Secrets`.
2. Select `New client secret` and provide a description to create new secret.
3. Note the `Value` of this secret which is required for the Elastic Microsoft Office 365 integration.

### Permissions for registered application

#### Audit Logs

Add permissions to your registered application to retrieve Office 365 audit logs using Management Activity API. 
1. Navigate to `API permissions` page and click `Add a permission`
2. Select `Office 365 Management APIs` tile from the listed tiles.
3. Click `Application permissions`.
4. Under `ActivityFeed`, select `ActivityFeed.Read` permission. This is minimum required permissions to read audit logs of your organization as [provided in the documentation](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference). Optionally, select `ActivityFeed.ReadDlp` to read DLP policy events.
5. Click `Add permissions`. 
6. If `User.Read` permission under `Microsoft.Graph` tile is not added by default, add this permission.
7. After the permissions are added, the admin has to grant consent for these permissions.

Please check [O365 Management API permissions](https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis#specify-the-permissions-your-app-requires-to-access-the-office-365-management-apis) for more details.

#### Usage Reports

1. Navigate to `Manage` --> `API permissions` and click `Add a permission`
2. Select `Microsoft Graph` tile from the listed tiles.
3. Click `Application permissions`.
4. Under `Reports`, select `Reports.Read.All` permission. This is minimum required permissions to read Microsoft 365 usage reports of your organization as [provided in the documentation](https://learn.microsoft.com/en-us/graph/permissions-reference#reportsreadall).
5. Click `Add permissions`.
6. After the permissions are added, the admin has to grant consent for these permissions.

### Additional Setup

By default for all Microsoft 365 usage reports, the user names, emails, group, or site information are anonymized by Microsoft using MD5 hashes. You can revert this change for a tenant and show identifiable user, group, and site information if your organization's privacy practices allow it. To do this, follow below steps:
1. Login to [Microsoft 365 admin center](https://admin.microsoft.com/)
2. Navigate to `Settings` --> `Org Settings` --> `Services` page.
3. Select `Reports`
4. Uncheck the statement `Display concealed user, group, and site names in all reports`, and then save your changes.

### Prepare

Once the secret is created and permissions are granted by admin, as you prepare to add Elastic Microsoft Office 365 integration, you will need to note/copy following:
1. `Application (client) ID` and `Directory (tenant) ID` in the registered application's `Overview` page.
2. `Value` from your application's secret.

### Setup Integration

Setup Elastic Agent's Microsoft O365 integration:

1. In Kibana navigate to `Management` --> `Integrations`.
2. In `Search for integrations` top bar, search for `Microsoft Office 365`.
3. Select the `Microsoft Office 365` integration from the search results.
4. Select "Add Microsoft Office 365" to add the integration.
5. Enable only `Collect logs and metrics from Office 365 using CEL Input`.
6. Under this section, enable `Collect Office 365 audit logs via Management Activity API using CEL Input` to retrieve Office 365 audit logs using Management Activity API. To retrieve Microsoft 365 Usage Report metrics, enable `Microsoft 365 Reports`.
7. Add `Directory (tenant) ID` noted in [Prepare](#prepare) step into `Directory (tenant) ID` parameter. This is required field.
8. Add `Application (client) ID` noted in [Prepare](#prepare) step into `Application (client) ID` parameter. This is required field.
9. Add the secret `Value` noted in [Prepare](#prepare) step into `Client Secret` parameter. This is required field.
10. Add/Modify any other parameters as necessary.

Microsoft default Oauth2 Token URL `https://login.microsoftonline.com` is used during the [oauth2 flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow). If not provided, the `Directory (tenant) ID` will be used for oauth2 token generation.

## Compatibility

The `ingest-geoip` and `ingest-user_agent` Elasticsearch plugins are required to run this module.

**NOTE:** As Microsoft is no longer supporting Azure Active Directory Authentication Library (ADAL), the existing o365audit input has been deprecated in favor of the [CEL](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html) input in version `1.18.0`. Hence for versions `>= 1.18.0`, certificate based authentication (provided by earlier o365audit input) is no longer supported. 

We request users upgrading from integration version `< 1.18.0` to `>= 1.18.0` to follow these steps:

1. Upgrade the Elastic Stack version to `>= 8.7.1`.
2. Upgrade the integration navigating via `Integrations -> Microsoft Office 365 -> Settings -> Upgrade`
3. Upgrade the integration policy navigating via `Integrations -> Microsoft Office 365 -> integration policies -> Version (Upgrade)`. If `Upgrade` option doesn't appear under the `Version`, that means the policy is already upgraded in the previous step. Please go to the next step.
4. Modify the integration policy:
    
    * Disable existing configuration (marked as `Deprecated`) and enable `Collect Office 365 audit logs via CEL` configuration.
    * Add the required parameters such as `Directory (tenant) ID`, `Application (client) ID`, `Client Secret` based on the previous configuration.
    * Verify/Update `Initial Interval` configuration parameter to start fetching events from. This defaults to 7 days. Even if there is overlap in times, the events are not duplicated.
    * Update the other configuration parameters as required and hit `Save Integration`.

Please refer [Upgrade an integration](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html) in case of any issues while performing integration upgrade.

## Logs

### Audit

Uses the Office 365 Management Activity API to retrieve audit messages from Office 365 and Azure AD activity logs. These are the same logs that are available under Audit Log Search in the Security and Compliance Center.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-02-07T16:43:53.000Z",
    "agent": {
        "ephemeral_id": "50dde7f7-f3a3-4597-9ce3-fd6c21fbe6df",
        "id": "a6ce2e4c-5271-405f-acc5-cb378534481d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "client": {
        "address": "213.97.47.133",
        "ip": "213.97.47.133"
    },
    "data_stream": {
        "dataset": "o365.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a6ce2e4c-5271-405f-acc5-cb378534481d",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "action": "PageViewed",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "code": "SharePoint",
        "dataset": "o365.audit",
        "id": "99d005e6-a4c6-46fd-117c-08d7abeceab5",
        "ingested": "2024-04-01T12:10:04Z",
        "kind": "event",
        "original": "{Site=d5180cfc-3479-44d6-b410-8c985ac894e3, ObjectId=https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/_layouts/15/onedrive.aspx, UserKey=i:0h.f|membership|1003200096971f55@live.com, ItemType=Page, OrganizationId=b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd, Operation=PageViewed, ClientIP=213.97.47.133, Workload=OneDrive, EventSource=SharePoint, RecordType=4, Version=1, UserId=asr@testsiem.onmicrosoft.com, WebId=8c5c94bb-8396-470c-87d7-8999f440cd30, CreationTime=2020-02-07T16:43:53, UserAgent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0, CustomUniqueId=true, Id=99d005e6-a4c6-46fd-117c-08d7abeceab5, CorrelationId=622b339f-4000-a000-f25f-92b3478c7a25, ListItemUniqueId=59a8433d-9bb8-cfef-6edc-4c0fc8b86875, UserType=0}",
        "outcome": "success",
        "provider": "OneDrive",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
        "name": "testsiem.onmicrosoft.com"
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "type": "ipv4"
    },
    "o365": {
        "audit": {
            "CorrelationId": "622b339f-4000-a000-f25f-92b3478c7a25",
            "CreationTime": "2020-02-07T16:43:53",
            "CustomUniqueId": true,
            "EventSource": "SharePoint",
            "ItemType": "Page",
            "ListItemUniqueId": "59a8433d-9bb8-cfef-6edc-4c0fc8b86875",
            "ObjectId": "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/_layouts/15/onedrive.aspx",
            "RecordType": "4",
            "Site": "d5180cfc-3479-44d6-b410-8c985ac894e3",
            "UserId": "asr@testsiem.onmicrosoft.com",
            "UserKey": "i:0h.f|membership|1003200096971f55@live.com",
            "UserType": "0",
            "Version": "1",
            "WebId": "8c5c94bb-8396-470c-87d7-8999f440cd30"
        }
    },
    "organization": {
        "id": "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd"
    },
    "related": {
        "ip": [
            "213.97.47.133"
        ],
        "user": [
            "asr"
        ]
    },
    "source": {
        "ip": "213.97.47.133"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "o365-cel"
    ],
    "user": {
        "domain": "testsiem.onmicrosoft.com",
        "email": "asr@testsiem.onmicrosoft.com",
        "id": "asr@testsiem.onmicrosoft.com",
        "name": "asr"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Firefox",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0",
        "os": {
            "full": "Mac OS X 10.14",
            "name": "Mac OS X",
            "version": "10.14"
        },
        "version": "72.0."
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| o365.audit.Activity |  | keyword |
| o365.audit.Actor.ID |  | keyword |
| o365.audit.Actor.Type |  | keyword |
| o365.audit.ActorContextId |  | keyword |
| o365.audit.ActorIpAddress |  | keyword |
| o365.audit.ActorUserId |  | keyword |
| o365.audit.ActorYammerUserId |  | keyword |
| o365.audit.AdditionalInfo.\* |  | object |
| o365.audit.AlertEntityId |  | keyword |
| o365.audit.AlertId |  | keyword |
| o365.audit.AlertLinks |  | flattened |
| o365.audit.AlertType |  | keyword |
| o365.audit.AppAccessContext.\* |  | object |
| o365.audit.AppId |  | keyword |
| o365.audit.ApplicationDisplayName |  | keyword |
| o365.audit.ApplicationId |  | keyword |
| o365.audit.AzureActiveDirectoryEventType |  | keyword |
| o365.audit.Category |  | keyword |
| o365.audit.ClientAppId |  | keyword |
| o365.audit.ClientIP |  | keyword |
| o365.audit.ClientIPAddress |  | keyword |
| o365.audit.ClientInfoString |  | keyword |
| o365.audit.ClientRequestId |  | keyword |
| o365.audit.Comments |  | text |
| o365.audit.CorrelationId |  | keyword |
| o365.audit.CreationTime |  | keyword |
| o365.audit.CustomUniqueId |  | boolean |
| o365.audit.Data.ad |  | keyword |
| o365.audit.Data.af |  | keyword |
| o365.audit.Data.aii |  | keyword |
| o365.audit.Data.ail |  | keyword |
| o365.audit.Data.alk |  | keyword |
| o365.audit.Data.als |  | keyword |
| o365.audit.Data.an |  | keyword |
| o365.audit.Data.at |  | date |
| o365.audit.Data.cid |  | keyword |
| o365.audit.Data.cpid |  | keyword |
| o365.audit.Data.dm |  | keyword |
| o365.audit.Data.dpn |  | keyword |
| o365.audit.Data.eid |  | keyword |
| o365.audit.Data.etps |  | keyword |
| o365.audit.Data.etype |  | keyword |
| o365.audit.Data.f3u |  | keyword |
| o365.audit.Data.flattened | The full Data document. | flattened |
| o365.audit.Data.fvs |  | keyword |
| o365.audit.Data.imsgid |  | keyword |
| o365.audit.Data.lon |  | keyword |
| o365.audit.Data.mat |  | keyword |
| o365.audit.Data.md |  | date |
| o365.audit.Data.ms |  | keyword |
| o365.audit.Data.od |  | keyword |
| o365.audit.Data.op |  | keyword |
| o365.audit.Data.ot |  | keyword |
| o365.audit.Data.plk |  | keyword |
| o365.audit.Data.pud |  | keyword |
| o365.audit.Data.reid |  | keyword |
| o365.audit.Data.rid |  | keyword |
| o365.audit.Data.sev |  | keyword |
| o365.audit.Data.sict |  | keyword |
| o365.audit.Data.sid |  | keyword |
| o365.audit.Data.sip |  | ip |
| o365.audit.Data.sitmi |  | keyword |
| o365.audit.Data.srt |  | keyword |
| o365.audit.Data.ssic |  | keyword |
| o365.audit.Data.suid |  | keyword |
| o365.audit.Data.tdc |  | keyword |
| o365.audit.Data.te |  | date |
| o365.audit.Data.thn |  | keyword |
| o365.audit.Data.tht |  | keyword |
| o365.audit.Data.tid |  | keyword |
| o365.audit.Data.tpid |  | keyword |
| o365.audit.Data.tpt |  | keyword |
| o365.audit.Data.trc |  | keyword |
| o365.audit.Data.ts |  | date |
| o365.audit.Data.tsd |  | keyword |
| o365.audit.Data.ttdt |  | date |
| o365.audit.Data.ttr |  | keyword |
| o365.audit.Data.upfc |  | keyword |
| o365.audit.Data.upfv |  | keyword |
| o365.audit.Data.ut |  | keyword |
| o365.audit.Data.von |  | keyword |
| o365.audit.Data.wl |  | keyword |
| o365.audit.Data.zfh |  | keyword |
| o365.audit.Data.zfn |  | keyword |
| o365.audit.Data.zmfh |  | keyword |
| o365.audit.Data.zmfn |  | keyword |
| o365.audit.Data.zu |  | keyword |
| o365.audit.DataType |  | keyword |
| o365.audit.EntityType |  | keyword |
| o365.audit.ErrorNumber |  | keyword |
| o365.audit.EventData |  | keyword |
| o365.audit.EventSource |  | keyword |
| o365.audit.ExceptionInfo.\* |  | object |
| o365.audit.ExchangeMetaData.\* |  | long |
| o365.audit.ExchangeMetaData.CC |  | keyword |
| o365.audit.ExchangeMetaData.MessageID |  | keyword |
| o365.audit.ExchangeMetaData.Sent |  | date |
| o365.audit.ExchangeMetaData.To |  | keyword |
| o365.audit.ExchangeMetaData.UniqueID |  | keyword |
| o365.audit.Experience |  | keyword |
| o365.audit.ExtendedProperties.\* |  | object |
| o365.audit.ExternalAccess |  | boolean |
| o365.audit.FileSizeBytes |  | long |
| o365.audit.GroupName |  | keyword |
| o365.audit.Id |  | keyword |
| o365.audit.ImplicitShare |  | keyword |
| o365.audit.IncidentId |  | keyword |
| o365.audit.InterSystemsId |  | keyword |
| o365.audit.InternalLogonType |  | keyword |
| o365.audit.IntraSystemId |  | keyword |
| o365.audit.Item.\* |  | object |
| o365.audit.Item.\*.\* |  | object |
| o365.audit.ItemName |  | keyword |
| o365.audit.ItemType |  | keyword |
| o365.audit.ListBaseType |  | keyword |
| o365.audit.ListId |  | keyword |
| o365.audit.ListItemUniqueId |  | keyword |
| o365.audit.LogonError |  | keyword |
| o365.audit.LogonType |  | keyword |
| o365.audit.LogonUserSid |  | keyword |
| o365.audit.MailboxGuid |  | keyword |
| o365.audit.MailboxOwnerMasterAccountSid |  | keyword |
| o365.audit.MailboxOwnerSid |  | keyword |
| o365.audit.MailboxOwnerUPN |  | keyword |
| o365.audit.Members |  | flattened |
| o365.audit.ModifiedProperties.\*.\* |  | object |
| o365.audit.Name |  | keyword |
| o365.audit.NewValue |  | keyword |
| o365.audit.ObjectDisplayName |  | keyword |
| o365.audit.ObjectId |  | keyword |
| o365.audit.ObjectType |  | keyword |
| o365.audit.Operation |  | keyword |
| o365.audit.OperationId |  | keyword |
| o365.audit.OperationProperties |  | object |
| o365.audit.OrganizationId |  | keyword |
| o365.audit.OrganizationName |  | keyword |
| o365.audit.OriginatingServer |  | keyword |
| o365.audit.Parameters.\* |  | object |
| o365.audit.Platform |  | keyword |
| o365.audit.PolicyDetails |  | flattened |
| o365.audit.PolicyId |  | keyword |
| o365.audit.RecordType |  | keyword |
| o365.audit.RequestId |  | keyword |
| o365.audit.ResultStatus |  | keyword |
| o365.audit.SensitiveInfoDetectionIsIncluded |  | boolean |
| o365.audit.SessionId |  | keyword |
| o365.audit.Severity |  | keyword |
| o365.audit.SharePointMetaData.\* |  | object |
| o365.audit.Site |  | keyword |
| o365.audit.SiteUrl |  | keyword |
| o365.audit.Source |  | keyword |
| o365.audit.SourceFileExtension |  | keyword |
| o365.audit.SourceFileName |  | keyword |
| o365.audit.SourceRelativeUrl |  | keyword |
| o365.audit.Status |  | keyword |
| o365.audit.SupportTicketId |  | keyword |
| o365.audit.Target.ID |  | keyword |
| o365.audit.Target.Type |  | keyword |
| o365.audit.TargetContextId |  | keyword |
| o365.audit.TargetUserOrGroupName |  | keyword |
| o365.audit.TargetUserOrGroupType |  | keyword |
| o365.audit.TeamGuid |  | keyword |
| o365.audit.TeamName |  | keyword |
| o365.audit.Timestamp |  | keyword |
| o365.audit.UniqueSharingId |  | keyword |
| o365.audit.UserAgent |  | keyword |
| o365.audit.UserId |  | keyword |
| o365.audit.UserKey |  | keyword |
| o365.audit.UserType |  | keyword |
| o365.audit.Version |  | keyword |
| o365.audit.WebId |  | keyword |
| o365.audit.Workload |  | keyword |
| o365.audit.WorkspaceId |  | keyword |
| o365.audit.WorkspaceName |  | keyword |
| o365.audit.YammerNetworkId |  | keyword |


## Metrics

### Microsoft 365 Reports

Uses the Microsoft Graph API to retrieve Microsoft 365 Usage Reports. These metrics are from the same reports/dashboards that are available under `Reports` --> `Usage` in the Microsoft 365 Admin Center.

An example event for `reports` looks as following:

```json
{
    "o365": {
        "reports": {
            "metadata": {
                "name": "Microsoft Teams User Activity User Detail",
                "api_path": "/reports/getTeamsUserActivityUserDetail"
            },
            "teams": {
                "user_activity": {
                    "user": {
                        "Meetings_Attended_Count": 0,
                        "Video_Duration_In_Seconds": 0,
                        "Screen_Share_Duration_In_Seconds": 0,
                        "Report_Period": "1",
                        "Screen_Share_Duration": "PT0S",
                        "Ad_Hoc_Meetings_Attended_Count": 0,
                        "Ad_Hoc_Meetings_Organized_Count": 0,
                        "Has_Other_Action": "No",
                        "Reply_Messages": 0,
                        "Tenant_Display_Name": "ABCD",
                        "Audio_Duration": "PT0S",
                        "Scheduled_Recurring_Meetings_Attended_Count": 0,
                        "Video_Duration": "PT0S",
                        "Is_Deleted": false,
                        "Audio_Duration_In_Seconds": 0,
                        "Assigned_Products": "MICROSOFT 365",
                        "Last_Activity_Date": "2024-12-17T00:00:00.000Z",
                        "Urgent_Messages": 0,
                        "Scheduled_One_time_Meetings_Attended_Count": 0,
                        "Report_Refresh_Date": "2024-12-17T00:00:00.000Z",
                        "Call_Count": 0,
                        "Is_Licensed": true,
                        "Private_Chat_Message_Count": 0,
                        "Scheduled_Recurring_Meetings_Organized_Count": 0,
                        "Scheduled_One_time_Meetings_Organized_Count": 0,
                        "Team_Chat_Message_Count": 1,
                        "Meetings_Organized_Count": 0,
                        "Post_Messages": 1,
                        "Meeting_Count": 0
                    }
                }
            }
        }
    },
    "input": {
        "type": "cel"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "02c7f2bd-8f60-456f-8651-e15cb4ddbe5c",
        "ephemeral_id": "acb55f0d-55db-4513-8480-b53bf6aeee8a",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "@timestamp": "2024-12-17T00:00:00.000Z",
    "ecs": {
        "version": "8.11.0"
    },
    "related": {
        "user": [
            "3cb1cad2-87d9-411c-8911-e72422342098",
            "user@abc.onmicrosoft.com"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365.reports"
    },
    "elastic_agent": {
        "id": "02c7f2bd-8f60-456f-8651-e15cb4ddbe5c",
        "version": "8.15.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-27T15:09:09Z",
        "original": "{\"Ad Hoc Meetings Attended Count\":\"0\",\"Ad Hoc Meetings Organized Count\":\"0\",\"Assigned Products\":\"MICROSOFT 365\",\"Audio Duration\":\"PT0S\",\"Audio Duration In Seconds\":\"0\",\"Call Count\":\"0\",\"Deleted Date\":\"\",\"Has Other Action\":\"No\",\"Is Deleted\":\"False\",\"Is Licensed\":\"Yes\",\"Last Activity Date\":\"2024-12-17\",\"Meeting Count\":\"0\",\"Meetings Attended Count\":\"0\",\"Meetings Organized Count\":\"0\",\"Post Messages\":\"1\",\"Private Chat Message Count\":\"0\",\"Reply Messages\":\"0\",\"Report Period\":\"1\",\"Scheduled One-time Meetings Attended Count\":\"0\",\"Scheduled One-time Meetings Organized Count\":\"0\",\"Scheduled Recurring Meetings Attended Count\":\"0\",\"Scheduled Recurring Meetings Organized Count\":\"0\",\"Screen Share Duration\":\"PT0S\",\"Screen Share Duration In Seconds\":\"0\",\"Shared Channel Tenant Display Names\":\"\",\"Team Chat Message Count\":\"1\",\"Tenant Display Name\":\"ABCD\",\"Urgent Messages\":\"0\",\"User Id\":\"3cb1cad2-87d9-411c-8911-e72422342098\",\"User Principal Name\":\"user@abc.onmicrosoft.com\",\"Video Duration\":\"PT0S\",\"Video Duration In Seconds\":\"0\",\"metadata\":{\"api_path\":\"/reports/getTeamsUserActivityUserDetail\",\"name\":\"Microsoft Teams User Activity User Detail\"},\"﻿Report Refresh Date\":\"2024-12-17\"}",
        "dataset": "o365.reports"
    },
    "user": {
        "name": "user@abc.onmicrosoft.com",
        "id": "3cb1cad2-87d9-411c-8911-e72422342098",
        "email": "user@abc.onmicrosoft.com"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "o365-reports"
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
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| o365.reports.metadata.api_path |  | keyword |
| o365.reports.metadata.name |  | keyword |
| o365.reports.office365.groups_activity.group.Exchange_Mailbox_Storage_Used_Byte |  | long |
| o365.reports.office365.groups_activity.group.Exchange_Mailbox_Total_Item_Count |  | long |
| o365.reports.office365.groups_activity.group.Exchange_Received_Email_Count |  | long |
| o365.reports.office365.groups_activity.group.External_Member_Count |  | long |
| o365.reports.office365.groups_activity.group.Group_Display_Name |  | keyword |
| o365.reports.office365.groups_activity.group.Group_Id |  | keyword |
| o365.reports.office365.groups_activity.group.Group_Type |  | keyword |
| o365.reports.office365.groups_activity.group.Is_Deleted |  | boolean |
| o365.reports.office365.groups_activity.group.Last_Activity_Date |  | date |
| o365.reports.office365.groups_activity.group.Member_Count |  | long |
| o365.reports.office365.groups_activity.group.Owner_Principal_Name |  | keyword |
| o365.reports.office365.groups_activity.group.Report_Period |  | keyword |
| o365.reports.office365.groups_activity.group.Report_Refresh_Date |  | date |
| o365.reports.office365.groups_activity.group.SharePoint_Active_File_Count |  | long |
| o365.reports.office365.groups_activity.group.SharePoint_Site_Storage_Used_Byte |  | long |
| o365.reports.office365.groups_activity.group.SharePoint_Total_File_Count |  | long |
| o365.reports.office365.groups_activity.group.Yammer_Liked_Message_Count |  | long |
| o365.reports.office365.groups_activity.group.Yammer_Posted_Message_Count |  | long |
| o365.reports.office365.groups_activity.group.Yammer_Read_Message_Count |  | long |
| o365.reports.onedrive.usage.account.Active_File_Count |  | long |
| o365.reports.onedrive.usage.account.File_Count |  | long |
| o365.reports.onedrive.usage.account.Is_Deleted |  | boolean |
| o365.reports.onedrive.usage.account.Last_Activity_Date |  | date |
| o365.reports.onedrive.usage.account.Owner_Display_Name |  | keyword |
| o365.reports.onedrive.usage.account.Owner_Principal_Name |  | keyword |
| o365.reports.onedrive.usage.account.Report_Period |  | keyword |
| o365.reports.onedrive.usage.account.Report_Refresh_Date |  | date |
| o365.reports.onedrive.usage.account.Site_Id |  | keyword |
| o365.reports.onedrive.usage.account.Site_URL |  | keyword |
| o365.reports.onedrive.usage.account.Storage_Allocated_Byte |  | long |
| o365.reports.onedrive.usage.account.Storage_Used_Byte |  | long |
| o365.reports.sharepoint.site_usage.site.Active_File_Count |  | long |
| o365.reports.sharepoint.site_usage.site.File_Count |  | long |
| o365.reports.sharepoint.site_usage.site.Is_Deleted |  | boolean |
| o365.reports.sharepoint.site_usage.site.Last_Activity_Date |  | date |
| o365.reports.sharepoint.site_usage.site.Owner_Display_Name |  | keyword |
| o365.reports.sharepoint.site_usage.site.Owner_Principal_Name |  | keyword |
| o365.reports.sharepoint.site_usage.site.Page_View_Count |  | long |
| o365.reports.sharepoint.site_usage.site.Report_Period |  | keyword |
| o365.reports.sharepoint.site_usage.site.Report_Refresh_Date |  | date |
| o365.reports.sharepoint.site_usage.site.Root_Web_Template |  | keyword |
| o365.reports.sharepoint.site_usage.site.Site_Id |  | keyword |
| o365.reports.sharepoint.site_usage.site.Site_URL |  | keyword |
| o365.reports.sharepoint.site_usage.site.Storage_Allocated_Byte |  | long |
| o365.reports.sharepoint.site_usage.site.Storage_Used_Byte |  | long |
| o365.reports.sharepoint.site_usage.site.Visited_Page_Count |  | long |
| o365.reports.teams.user_activity.user.Ad_Hoc_Meetings_Attended_Count |  | long |
| o365.reports.teams.user_activity.user.Ad_Hoc_Meetings_Organized_Count |  | long |
| o365.reports.teams.user_activity.user.Assigned_Products |  | keyword |
| o365.reports.teams.user_activity.user.Audio_Duration |  | keyword |
| o365.reports.teams.user_activity.user.Audio_Duration_In_Seconds |  | long |
| o365.reports.teams.user_activity.user.Call_Count |  | long |
| o365.reports.teams.user_activity.user.Deleted_Date |  | date |
| o365.reports.teams.user_activity.user.Has_Other_Action |  | keyword |
| o365.reports.teams.user_activity.user.Is_Deleted |  | boolean |
| o365.reports.teams.user_activity.user.Is_Licensed |  | boolean |
| o365.reports.teams.user_activity.user.Last_Activity_Date |  | date |
| o365.reports.teams.user_activity.user.Meeting_Count |  | long |
| o365.reports.teams.user_activity.user.Meetings_Attended_Count |  | long |
| o365.reports.teams.user_activity.user.Meetings_Organized_Count |  | long |
| o365.reports.teams.user_activity.user.Post_Messages |  | long |
| o365.reports.teams.user_activity.user.Private_Chat_Message_Count |  | long |
| o365.reports.teams.user_activity.user.Reply_Messages |  | long |
| o365.reports.teams.user_activity.user.Report_Period |  | keyword |
| o365.reports.teams.user_activity.user.Report_Refresh_Date |  | date |
| o365.reports.teams.user_activity.user.Scheduled_One_time_Meetings_Attended_Count |  | long |
| o365.reports.teams.user_activity.user.Scheduled_One_time_Meetings_Organized_Count |  | long |
| o365.reports.teams.user_activity.user.Scheduled_Recurring_Meetings_Attended_Count |  | long |
| o365.reports.teams.user_activity.user.Scheduled_Recurring_Meetings_Organized_Count |  | long |
| o365.reports.teams.user_activity.user.Screen_Share_Duration |  | keyword |
| o365.reports.teams.user_activity.user.Screen_Share_Duration_In_Seconds |  | long |
| o365.reports.teams.user_activity.user.Shared_Channel_Tenant_Display_Names |  | keyword |
| o365.reports.teams.user_activity.user.Team_Chat_Message_Count |  | long |
| o365.reports.teams.user_activity.user.Tenant_Display_Name |  | keyword |
| o365.reports.teams.user_activity.user.Urgent_Messages |  | long |
| o365.reports.teams.user_activity.user.User_Id |  | keyword |
| o365.reports.teams.user_activity.user.User_Principal_Name |  | keyword |
| o365.reports.teams.user_activity.user.Video_Duration |  | keyword |
| o365.reports.teams.user_activity.user.Video_Duration_In_Seconds |  | long |
| o365.reports.viva_engage.groups_activity.group.Group_Display_Name |  | keyword |
| o365.reports.viva_engage.groups_activity.group.Group_Type |  | keyword |
| o365.reports.viva_engage.groups_activity.group.Is_Deleted |  | boolean |
| o365.reports.viva_engage.groups_activity.group.Last_Activity_Date |  | date |
| o365.reports.viva_engage.groups_activity.group.Liked_Count |  | long |
| o365.reports.viva_engage.groups_activity.group.Member_Count |  | long |
| o365.reports.viva_engage.groups_activity.group.Office_365_Connected |  | boolean |
| o365.reports.viva_engage.groups_activity.group.Owner_Principal_Name |  | keyword |
| o365.reports.viva_engage.groups_activity.group.Posted_Count |  | long |
| o365.reports.viva_engage.groups_activity.group.Read_Count |  | long |
| o365.reports.viva_engage.groups_activity.group.Report_Period |  | keyword |
| o365.reports.viva_engage.groups_activity.group.Report_Refresh_Date |  | date |

