# Microsoft Office 365 Integration

This integration is for [Microsoft Office 365](https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/). It currently supports user, admin, system, and policy actions and events from Office 365 and Azure AD activity logs exposed by the [Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference).

## Setup

To use this integration you need to [enable `Audit Log`](https://learn.microsoft.com/en-us/purview/audit-log-enable-disable) and register an application in [Microsoft Entra ID (formerly known as Azure Active Directory)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id).

Once the Microsoft Entra ID application is registered, you can set up its credentials and permissions, and gather the information needed by the Microsoft Office 365 Elastic integration, as follows:

1. Note the `Application (client) ID` and `Directory (tenant) ID` in the registered application's `Overview` page.
2. Create a new secret to configure the authentication of your application, as follows:
    - Navigate to `Certificates & Secrets` section.
    - Click `New client secret`, provide a description and create the new secret.
    - Note the `Value` which is required for setup of the integration.
3. Add permissions to your registered application. Please refer to the [Office 365 Management API documentation](https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis#specify-the-permissions-your-app-requires-to-access-the-office-365-management-apis) for more details.
    - Navigate to `API permissions` page and click `Add a permission`
    - Select `Office 365 Management APIs` tile from the listed tiles.
    - Click `Application permissions`.
    - Under `ActivityFeed`, select `ActivityFeed.Read` permission. This is minimum required permissions to read audit logs of your organization as [provided in the documentation](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference). Optionally, select `ActivityFeed.ReadDlp` to read DLP policy events.
    - Click `Add permissions`.
    - If `User.Read` permission under `Microsoft.Graph` tile is not added by default, add this permission.
    - After the permissions are added, the admin has to grant consent for these permissions.

The instructions above assume that you wish to collect data from your own tenant. If that is not the case, additional steps are required to obtain tenant admin consent for the required permissions. The API documenation describes [a method of gathering consent via redirect URLs](https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis#get-office-365-tenant-admin-consent), and other consent flows may be possible.

### Troubleshooting

In the case of a permissions issue, it can be useful to enable request tracing and look at request trace logs to inspect the interaction with the server. Token values can be decoded using [https://jwt.ms/](https://jwt.ms/), and should include a `roles` section with the configured permissions.

### Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent and Agentless Setup

Once the secret is created and permissions are granted by admin, setup Elastic Agent's Microsoft O365 integration:
- Click `Add Microsoft Office 365`.
- Enable `Collect Office 365 audit logs via Management Activity API using CEL Input`.
- Add `Directory (tenant) ID` noted in Step 1 into `Directory (tenant) ID` parameter. This is required field.
- Add `Application (client) ID` noted in Step 1 into `Application (client) ID` parameter. This is required field.
- Add the secret `Value` noted in Step 2 into `Client Secret` parameter. This is required field.
- Oauth2 Token URL can be added to generate the tokens during the oauth2 flow. If not provided, above `Directory (tenant) ID` will be used for oauth2 token generation.
- Modify any other parameters as necessary.

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

## Compatibility

The `ingest-geoip` and `ingest-user_agent` Elasticsearch plugins are required to run this module.

## Logs

### Audit

Uses the Office 365 Management Activity API to retrieve audit messages from Office 365 and Azure AD activity logs. These are the same logs that are available under Audit Log Search in the Security and Compliance Center.

{{event "audit"}}

{{fields "audit"}}
