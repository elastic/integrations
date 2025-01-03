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

{{event "audit"}}

{{fields "audit"}}

## Metrics

### Microsoft 365 Reports

Uses the Microsoft Graph API to retrieve Microsoft 365 Usage Reports. These metrics are from the same reports/dashboards that are available under `Reports` --> `Usage` in the Microsoft 365 Admin Center.

{{event "reports"}}

{{fields "reports"}}
