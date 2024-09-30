# Salesforce Integration

## Overview

The Salesforce integration enables you to monitor your [Salesforce](https://www.salesforce.com/) instance. Salesforce is a customer relationship management (CRM) platform that supports businesses in managing marketing, sales, commerce, service, and IT teams from a unified platform accessible from anywhere.

You can use the Salesforce integration for:

- **Operational insights**: Gain valuable insights into your organization's login and logout activities and other operational events.

- **Data visualization**: Create detailed visualizations to monitor, measure, and analyze usage trends and key data, helping you derive actionable business insights.

- **Proactive alerts**: Set up alerts to minimize Mean Time to Detection (MTTD) and Mean Time to Resolution (MTTR) by referencing relevant logs during troubleshooting.

## Data streams

The Salesforce integration collects the following data streams:

- `login`: Collects information related to users who log in to Salesforce.
- `logout`: Collects information related to users who log out from Salesforce.
- `apex`: Collects information about various Apex events such as Callout, Execution, REST API, SOAP API, Trigger, and so on.
- `setupaudittrail`: Collects information related to changes users made in the organization's setup area for the last 180 days.

The Salesforce integration collects the following events using the Salesforce REST API:

- [Login EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_login.htm)
- [Login Platform Events](https://developer.salesforce.com/docs/atlas.en-us.236.0.platform_events.meta/platform_events/sforce_api_objects_logineventstream.htm)
- [Logout EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_logout.htm)
- [Logout Platform Events](https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_logouteventstream.htm)
- [Apex EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.238.0.object_reference.meta/object_reference/sforce_api_objects_apexclass.htm)
- [SetupAuditTrail Object](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_setupaudittrail.htm)

## Compatibility

This integration has been tested against the Salesforce Spring '22 (v54.0) release. The minimum supported version is v46.0.

To determine your Salesforce instance version, use one of the following methods:

- Salesforce Classic

  On the **Home** tab in Salesforce Classic, you can find a link in the top right corner that indicates the current release version of your Salesforce instance, for example `Summer '24 for Developers`.

- Use the Salesforce Instance URL

  Use your Salesforce Instance URL with the following format: `<Salesforce Instance URL>/services/data`, for example: `https://na9.salesforce.com/services/data`, here `https://na9.salesforce.com` is the Salesforce Instance URL.

This will return an XML response listing with available API versions:

```xml
<Versions>
    <Version>
        <label>Winter '22</label>
        <url>/services/data/v53.0</url>
        <version>53.0</version>
    </Version>
    <Version>
        <label>Spring '22</label>
        <url>/services/data/v54.0</url>
        <version>54.0</version>
    </Version>
    <Version>
        <label>Summer '22</label>
        <url>/services/data/v55.0</url>
        <version>55.0</version>
    </Version>
</Versions>
```

The last entry in the list indicates the current release version of your Salesforce instance. In this example, the version is `Summer '22 (v55.0)`.

## Prerequisites

- You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

- Make sure API Enabled permission is selected for the user profile in your Salesforce instance:

  1. Go to **Setup** > **Quick Find** and type **Users**.
  2. Select **Users** from the left navigation tree.
  3. In the **Full Name** column, select the name associated with the user account used for data collection.
  4. Search for the **API Enabled** permission on the profile page. If it’s not present, search under **System Permissions** and check if the API Enabled privilege is selected. If not, enable it for data collection.

- Make sure that collecting data using [Real-Time Event Monitoring API](https://help.salesforce.com/s/articleView?id=sf.real_time_event_monitoring_enable.htm&type=5) is enabled:

  1. Go to **Setup** > **Quick Find** and type **Event Manager**.
  2. Select **Event Manager** from the left navigation tree.
  3. To monitor an event, for example, Login Event, or Logout Event, click the dropdown arrow and select **Enable Storage**.
  4. Check if you have the required permissions: **View Real-Time Event Monitoring Data**.

**Note**: Real-Time Event Monitoring may require additional licensing. Check your subscription level with your Salesforce account representative.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Configuration

To configure the Salesforce integration, you need the following information:

- [Salesforce instance URL](#salesforce-instance-url)
- [Client key and client secret for authentication](#client-key-and-client-secret-for-authentication)
- [Username](#username)
- [Password](#password)
- [API version](#api-version)

### Salesforce instance URL

This is the URL of your Salesforce Organization.

- **Salesforce Classic**: Given the example URL https://na9.salesforce.com/home/home.jsp, the Salesforce Instance URL is extracted as https://na9.salesforce.com.

- **Salesforce Lightning**: The instance URL is available under your user name in the **View Profile** tab.

### Client key and client secret for authentication

To use this integration, you need to create a new Salesforce Application using OAuth. Follow these steps to create a connected application in Salesforce:

1. Log in to [Salesforce](https://login.salesforce.com/) with the user credentials you want to collect data with.
2. Click **Setup** in the top right menu bar.
3. In the **Search Setup** box, search for `App Manager` and select it.
4. Click **New Connected App**.
5. Provide a name for the connected application. This name will be displayed in the App Manager and on its App Launcher tile.
6. Enter the API name. The default is a version of the name without spaces. Only letters, numbers, and underscores are allowed. If the original app name contains any other characters, edit the default name.
7. Enter the contact email for Salesforce.
8. In the **API (Enable OAuth Settings)** section, select **Enable OAuth Settings**.
9. In the **Callback URL** field, enter the instance URL as described in [Salesforce instance URL](#salesforce-instance-url).
10. Select the following OAuth scopes to apply to the connected app:
    - **Manage user data via APIs (api)**
    - **Perform requests at any time (refresh_token, offline_access)**
    - (Optional) If you encounter any permission issues during data collection, add the **Full access (full)** scope.
11. Select **Require Secret for the Web Server Flow** to require the app's client secret in exchange for an access token.
12. Select **Require Secret for Refresh Token Flow** to require the app's client secret in the authorization request of a refresh token and hybrid refresh token flow.
13. Click **Save**. It may take approximately 10 minutes for the changes to take effect.
14. Click **Continue**, then under **API details**, click **Manage Consumer Details**. Verify the user account using the Verification Code.
15. Copy the `Consumer Key` and `Consumer Secret` from the Consumer Details section. These should be populated as the values for Client ID and Client Secret, respectively, in the configuration.

For more details, check the Salesforce documentation on how to [Create a Connected App](https://help.salesforce.com/apex/HTViewHelpDoc?id=connected_app_create.htm).

### Username

The User ID of the registered user.

### Password

The password used to authenticate the user.

### API version

To find the API version:

1. Go to `Setup` > `Quick Find` > `Apex Classes`.
2. Click `New`.
3. Click the `Version Settings` tab.
4. Refer to the `Version` dropdown for the API Version number.

## Validation

Once the Salesforce integration is successfully configured, follow these steps to validate the setup:

1. Navigate to the **Assets** tab in the Salesforce Integration. You will find a list of available dashboards related to your configured data streams.
2. Select the dashboard relevant to your data stream (for example, login, logout, apex, setupaudittrail).
3. Verify that the dashboard is populated with the expected data.

If the dashboard displays the data correctly, your integration is successfully validated.

## Salesforce Integration: v0.15.0 and Beyond

With version 0.15.0, we've significantly enhanced the Salesforce integration, introducing major changes in data collection mechanisms, authentication, and data streams. Due to these changes, we recommend using Salesforce integration v0.15.0 or above and uninstalling previous versions.

### Key enhancements

1. Unified data collection: The integration now uses a single Filebeat input ([Salesforce input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-salesforce.html)) for data collection from EventLogFile and Real-time Event Monitoring APIs.
2. JWT authentication: Introduced JWT authentication mechanism.
3. Expanded configuration options: Added `initial_interval` and other options to fine-tune data collection, including historical data retrieval.
4. Change in data-collection mechanism: Replaced Streaming API (cometd) with Real-time Event Monitoring APIs.
5. Performance optimization: Significantly reduced CPU and memory usage during data collection.
6. Enhanced dashboards: Improved visualizations.

### Breaking changes

1. Data stream consolidation: Reduced from 6 to 4 data streams — `apex`, `login`, `logout`, and `setupaudittrail`.
2. Field mapping updates: Modified mappings for multiple fields.
3. Additional changes: Various other modifications to enhance the overall integration performance and functionality.

## Troubleshooting

This section provides solutions to common issues you might encounter while using the Salesforce integration.

### Request timeout

If you experience delays in the response from the Salesforce server in the `apex`, `login`, `logout`, or `setupaudittrail` data streams, you might encounter the following error:

```
Error while processing http request: failed to execute rf.collectResponse: failed to execute http client.Do: failed to execute http client.Do: failed to read http.response.body
```

**Solution:** Consider increasing the `Request timeout` setting in the `Advanced options` section for the affected data stream.

### Data ingestion error

If you encounter data ingestion errors, you might get the following error message:

> oauth2 client: error loading credentials using user and password: oauth2: cannot fetch token: 400 Bad Request

**Solution:** Make sure that the `API Enabled` permission is granted to the `profile` associated with the `username` used for the integration. Check the [Prerequisites](#prerequisites) section for more information.

If the error persists, follow these steps:

1. Go to **Setup** > **Quick Find** > **App Manager**.
2. Find the app and click the corresponding arrow to check which actions are available.
3. Click **View**.
4. Get the key and secret by clicking **Manage Consumer Details** in the API section.
5. Click **Manage** to edit the policies.
6. Click **Edit Policies** and select **Relax IP restrictions** from the dropdown for IP Relaxation.

## Logs reference

### Apex

The `apex` data stream captures events related to Apex operations, enabling developers to access the Salesforce platform back-end database and client-server interfaces to create third-party SaaS applications.

{{event "apex"}}

{{fields "apex"}}

### Login

The `login` data stream captures events that detail the login history of users within your Salesforce organization. This data stream provides insights into user authentication activities, helping you monitor and analyze login patterns, detect anomalies, and ensure security compliance.

{{event "login"}}

{{fields "login"}}

### Logout

The `logout` data stream captures events that detail the logout history of users within your Salesforce organization. This data stream provides insights into user authentication activities, helping you monitor and analyze logout patterns, detect anomalies, and ensure security compliance.

{{event "logout"}}

{{fields "logout"}}

### SetupAuditTrail

The `setupaudittrail` data stream captures and records changes made by users in the organization's Setup area. By default, it collects data from the last week, but users can configure it to collect data from up to the last 180 days by adjusting the initial interval in the configuration.

{{event "setupaudittrail"}}

{{fields "setupaudittrail"}}
