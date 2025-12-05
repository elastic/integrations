# Microsoft Office 365 Integration

## Overview
This integration is for [Microsoft Office 365](https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/).

### How it works

The integration works by collecting user, admin, system, and policy actions, as well as events from Office 365 and Azure AD activity logs exposed by the [Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference).

### Compatibility

- **API Version**: The Microsoft Office 365 integration is compatible with version 1.0 of Microsoft Office 365 Management API.
- **Supported Workloads**: This integration supports the following Microsoft Office 365 workloads:
  - Audit.AzureActiveDirectory
  - Audit.Exchange
  - Audit.SharePoint
  - Audit.General
  - DLP.All

For detailed information on the supported record types within these workloads, please refer to the [AuditLogRecordType documentation](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype).

## What data does this integration collect?

This integration collects log messages of the following types:

- `Audit`: Uses the [Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference) to retrieve audit messages from Office 365 and Azure AD activity logs. These are the same logs that are available under Audit Log Search in the Microsoft Purview portal.

### Supported use cases

Integrating Microsoft Office 365 with Elastic SIEM enables collection of audit logs for monitoring and analysis, which can then be visualized in Kibana.

## What do I need to use this integration?

To use this integration you need to [enable `Audit Log`](https://learn.microsoft.com/en-us/purview/audit-log-enable-disable) and register an application in [Microsoft Entra ID (formerly known as Azure Active Directory)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id).

Once the Microsoft Entra ID application is registered, you can set up its credentials and permissions, and gather the information needed by the Microsoft Office 365 Elastic integration, as follows:

1. Note the `Application (client) ID` and `Directory (tenant) ID` in the registered application's `Overview` page.
2. Create a new secret to configure the authentication of your application, as follows:
    - Navigate to `Manage -> Certificates & Secrets` section.
    - Click `New client secret`, provide a description and create the new secret.
      ![New Client Secret](../img/new_client_secrets.png)
    - Note the `Value` which is required for setup of the integration.
      ![Value](../img/value.png)
3. Add permissions to your registered application. Please refer to the [Office 365 Management API documentation](https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis#specify-the-permissions-your-app-requires-to-access-the-office-365-management-apis) for more details.
    - Navigate to `Manage -> API permissions` page. Under Configured permissions click `Add a permission`.
    - Select `Office 365 Management APIs` tile from the listed tiles.
      ![Select management API](../img/select_management_api.png)
    - Click `Application permissions`.
      ![API Permission](../img/permission_type.png)
    - Under `ActivityFeed`, select `ActivityFeed.Read` permission. This is minimum required permissions to read audit logs of your organization as [provided in the documentation](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference). Optionally, select `ActivityFeed.ReadDlp` to read DLP policy events.
    - Click `Add permissions`.
      ![Required Permission](../img/required_permission.png)
    - If `User.Read` permission under `Microsoft.Graph` tile is not added by default, add this permission.
    - After the permissions are added, the admin has to grant consent for these permissions.

The instructions above assume that you wish to collect data from your own tenant. If that is not the case, additional steps are required to obtain tenant admin consent for the required permissions. The API documentation describes [a method of gathering consent via redirect URLs](https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis#get-office-365-tenant-admin-consent), and other consent flows may be possible.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Microsoft Office 365**.
3. Select the **Microsoft Office 365** integration from the search results.
4. Select **Add Microsoft Office 365** to add the integration.
5. Enable and configure only the collection methods which you will use.
   - To **Collect audit logs**, you'll need to configure **Application (client) ID**, **Client Secret** and **Directory (tenant) ID**.
   - Do not use **DEPRECATED - Collect audit logs** as it's deprecated.
6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Microsoft Office 365**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **o365**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

### Troubleshooting

In the case of a permissions issue, it can be useful to enable request tracing and look at request trace logs to inspect the interaction with the server. Token values can be decoded using [https://jwt.ms/](https://jwt.ms/), and should include a `roles` section with the configured permissions.

When errors occur in the Microsoft Office 365 integration while collecting data, refer to the Office 365 Management Activity API documentation for the full list of error codes and their meanings. See the official [Office 365 Management Activity API — Errors](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference#errors).

### Migration From the Deprecated o365audit Input

**NOTE:** As Microsoft is no longer supporting Azure Active Directory Authentication Library (ADAL), the existing o365audit input has been deprecated in favor of the [CEL](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html) input in version `1.18.0`. Hence for versions `>= 1.18.0`, certificate based authentication (provided by earlier o365audit input) is no longer supported.

We request that users upgrading from integration version `< 1.18.0` to `>= 1.18.0` follow these steps:

1. Upgrade the Elastic Stack version to `>= 8.7.1`.
2. Upgrade the integration navigating via `Integrations -> Microsoft Office 365 -> Settings -> Upgrade`
3. Upgrade the integration policy navigating via `Integrations -> Microsoft Office 365 -> integration policies -> Version (Upgrade)`. If `Upgrade` option doesn't appear under the `Version`, that means the policy is already upgraded in the previous step. Please go to the next step.
4. Modify the integration policy:
    * Disable existing configuration (marked as `Deprecated`) and enable `Collect Office 365 audit logs via CEL` configuration.
    * Add the required parameters such as `Directory (tenant) ID`, `Application (client) ID`, `Client Secret` based on the previous configuration.
    * Verify/Update `Initial Interval` configuration parameter to start fetching events from. This defaults to 7 days. Even if there is overlap in times, the events are not duplicated.
    * Update the other configuration parameters as required and hit `Save Integration`.

Please refer [Upgrade an integration](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html) in case of any issues while performing integration upgrade.

## Data latency

This integration works by creating a subscription for each enabled content type, checking each subscription for available data, and downloading any data that is available.

As discussed in Microsoft's [Working with the Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference#working-with-the-office-365-management-activity-api) documentation, when a subscription is first created it can take up to 12 hours for the first data to become available. Users of this integration should expect to see that initial delay.

Data may become available out of order, so the earliest data will not necessarily be downloaded first. Data will be downloaded in the order in which it becomes available.

If a new integration policy is created to fetch data from existing subscriptions, earlier data may be available and the integration will try to fetch it. This can help to fill short gaps in data. The Initial Interval setting controls how far back it will look. By default it will check for data that became available in the last week, which is the maximum time range allowed by the API.

## Reference

### Logs reference

#### Audit
{{event "audit"}}

### ECS field reference

#### Audit
{{fields "audit"}}

### Inputs used

These inputs are used in this integration:
- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
- [o365-module (DEPRECATED)](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-module-o365)

### API usage

This integration dataset uses the following APIs:
- `Audit`: [Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference)
