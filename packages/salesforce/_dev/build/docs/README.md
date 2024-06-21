# Salesforce Integration

## Overview

The Salesforce integration enables users to monitor their [Salesforce](https://www.salesforce.com/) instance effectively. Salesforce is a comprehensive customer relationship management (CRM) platform that supports businesses in managing marketing, sales, commerce, service, and IT teams from a unified platform accessible from anywhere.

### Key Benefits of Salesforce Integration:

- **Operational Insights**: Gain valuable insights into login and logout activities and other operational events within your organization.
- **Data Visualization**: Create detailed visualizations to monitor, measure, and analyze usage trends and key data, helping you derive actionable business insights.
- **Proactive Alerts**: Set up alerts to minimize Mean Time to Detection (MTTD) and Mean Time to Resolution (MTTR) by referencing relevant logs during troubleshooting.

## Data streams

The Salesforce integration collects log events using the Salesforce REST API.

Logs help users maintain a record of events occurring in Salesforce. The log data streams collected by the Salesforce integration include:

- [Login EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_login.htm)
- [Login Platform Events](https://developer.salesforce.com/docs/atlas.en-us.236.0.platform_events.meta/platform_events/sforce_api_objects_logineventstream.htm)
- [Logout EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_logout.htm)
- [Logout Platform Events](https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_logouteventstream.htm)
- [Apex EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.238.0.object_reference.meta/object_reference/sforce_api_objects_apexclass.htm)
- [SetupAuditTrail Object](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_setupaudittrail.htm).

Data streams:
- `login`: Tracks login activity of users who log in to Salesforce.
- `logout`: Tracks logout activity of users who log out from Salesforce.
- `apex`: Represents information about various Apex events such as Callout, Execution, REST API, SOAP API, Trigger, etc.
- `setupaudittrail`: Represents changes users made in the organization's setup area for at least the last 180 days.

## Compatibility

This integration has been tested against Salesforce Spring '22 (v54.0) release.

You can find the Salesforce instance version by using the following methods:

1. Salesforce Classic: On the Home tab in Salesforce Classic, in the top right corner of the screen is a link to releases like `Summer '22`. This indicates the release version of the salesforce instance.

2. Using the Salesforce Instance URL: To find out the version of Salesforce is by using the instance URL:
    - Format: (Salesforce Instance URL)/services/data
    - Example: `https://na9.salesforce.com/services/data`

Example response:

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

The last one on the list is the release of the user's salesforce instance. In the example above, the version is `Summer '22` i.e. `v55.0`.

The last entry in the list indicates the current release version of your Salesforce instance. In the example above, the version is `Summer '22 (v55.0)`.

## Prerequisites

To use this integration, you need Elasticsearch for storing and searching your data, and Kibana for visualizing and managing it. We recommend using our hosted Elasticsearch Service on Elastic Cloud, but you can also self-manage the Elastic Stack on your own hardware.

### Enabling API Access in Salesforce

Ensure that the `API Enabled` permission is selected for the user profile in your Salesforce instance. Follow these steps to enable it:

1. Navigate to `Setup` > `Quick Find` > `Users`, and click on `Users`.
2. Click on the profile link associated with the `User Account` used for data collection.
3. Search for the `API Enabled` permission on the profile page. If it’s not present, search under `System Permissions` and check if the `API Enabled` privilege is selected. If not, enable it for data collection.

### Collecting Data Using Streaming API

Ensure that the `View Real-Time Event Monitoring Data` permission is selected for the user profile in your Salesforce instance. Follow these steps to enable it:

1. Navigate to `Setup` > `Quick Find` > `Users`, and click on `Users`.
2. Click on the profile link associated with the `User Account` used for data collection.
3. Search for the `View Real-Time Event Monitoring Data` permission on the profile page. If it’s not present, search under `System Permissions` and check if the `View Real-Time Event Monitoring Data` privilege is selected. If not, enable it for data collection.

### Enabling Event Streaming

Ensure that `Event Streaming` is enabled for both `Login Event` and `Logout Event`. Follow these steps to enable it:

1. Navigate to `Setup` > `Quick Find` > `Event Manager`, and click on `Event Manager`.
2. For both `Login Event` and `Logout Event`, click on the down arrow button on the left corner and select `Enable Streaming`.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

> **Note:** Please enable either the `login` data stream or the `logout` data stream to avoid data duplication.

## Configuration

To configure the Salesforce integration in Elastic, you will need the following information from your Salesforce instance:

### Salesforce Instance URL

The Salesforce Instance URL is the URL of your Salesforce Organization. It can be found in the address bar in Salesforce Classic or Salesforce Lightning.

- **Salesforce Classic**: The value before 'salesforce.com' in the URL is your Salesforce Instance.

  Example URL: `https://na9.salesforce.com/home/home.jsp`

  In this example, the Salesforce Instance URL is: `https://na9.salesforce.com`

- **Salesforce Lightning**: The instance URL is available under your user name in the “View Profile” tab.

### Client Key and Client Secret for Authentication

To use this integration, you need to create a new Salesforce Application using OAuth. Follow these steps to create a connected application in Salesforce:

1. Log in to [Salesforce](https://login.salesforce.com/) with the user credentials you want to collect data with.
2. Click on **Setup** in the top right menu bar.
3. In the Setup page, search for `App Manager` in the `Search Setup` box at the top of the page, then select **App Manager**.
4. Click **New Connected App**.
5. Provide a name for the connected application. This name will be displayed in the App Manager and on its App Launcher tile.
6. Enter the API name. The default is a version of the name without spaces. Only letters, numbers, and underscores are allowed. If the original app name contains any other characters, edit the default name.
7. Enter the contact email for Salesforce.
8. Under the **API (Enable OAuth Settings)** section, select **Enable OAuth Settings**.
9. In the **Callback URL**, enter the Instance URL (refer to `Salesforce Instance URL` above).
10. Select the following OAuth scopes to apply to the connected app:
    - **Manage user data via APIs (api)**
    - **Perform requests at any time (refresh_token, offline_access)**
    - (Optional) If you encounter any permission issues during data collection, add the **Full access (full)** scope.
11. Select **Require Secret for the Web Server Flow** to require the app's client secret in exchange for an access token.
12. Select **Require Secret for Refresh Token Flow** to require the app's client secret in the authorization request of a refresh token and hybrid refresh token flow.
13. Click **Save**. It may take approximately 10 minutes for the changes to take effect.
14. Click **Continue**, then under **API details**, click **Manage Consumer Details**. Verify the user account using the Verification Code.
15. Copy the `Consumer Key` and `Consumer Secret` from the Consumer Details section. These should be populated as the values for Client ID and Client Secret, respectively, in the configuration.

For more details on how to create a connected app, refer to the Salesforce documentation [here](https://help.salesforce.com/apex/HTViewHelpDoc?id=connected_app_create.htm).

### Username

The User ID of the registered user in Salesforce.

### Password

The password used for authenticating the above user.

## Additional Information

Follow the steps below if you need to find the API version:

1. Go to `Setup` > `Quick Find` > `Apex Classes`.
2. Click the `New` button.
3. Click the `Version Settings` tab.
4. Refer to the `Version` dropdown for the API Version number.

## Validation

Once the Salesforce integration is successfully configured, you can validate the setup by following these steps:

1. Navigate to the **Assets** tab within the Salesforce Integration.
2. You should see a list of available dashboards corresponding to your configured data streams.
3. Select the dashboard relevant to your data stream (e.g., login, logout, apex, setupaudittrail).
4. Verify that the dashboard is populated with the expected data.

If the dashboard displays the data correctly, your integration is successfully validated.


## Troubleshooting

This section provides solutions to common issues you might encounter while using the Salesforce integration.

### Request timeout

If you experience delays in the response from the Salesforce server in the `Apex`, `Login Rest`, `Logout Rest`, or `SetupAuditTrail` data streams, you might encounter the following error:

```
Error while processing http request: failed to execute rf.collectResponse: failed to execute http client.Do: failed to execute http client.Do: failed to read http.response.body
```

**Solution:** Consider increasing the `Request timeout` configuration from the `Advanced options` section of the affected data stream.

### Data ingestion error

If you encounter data ingestion errors, you might see logs similar to the following:

```json
{
    "log.level": "error",
    "@timestamp": "2022-11-24T12:59:36.835+0530",
    "log.logger": "input.httpjson-cursor",
    "log.origin": {
        "[file.name](http://file.name/)": "compat/compat.go",
        "file.line": 124
    },
    "message": "Input 'httpjson-cursor' failed with: input.go:130: input 8A049E17A5CA661D failed (id=8A049E17A5CA661D)\n\toauth2 client: error loading credentials using user and password: oauth2: cannot fetch token: 400 Bad Request\n\tResponse: {\"error\":\"invalid_grant\",\"error_description\":\"authentication failure\"}",
    "[service.name](http://service.name/)": "filebeat",
    "id": "8A049E17A5CA661D",
    "ecs.version": "1.6.0"
}
```

**Solution:** Ensure that the `API Enabled` permission is provided to the `profile` associated with the `username` used for the integration. Refer to the **Prerequisites** section above for more information.

If the error persists, follow these steps:

1. Go to `Setup` > `Quick Find` > `Manage Connected Apps`.
2. Click on the Connected App name created to generate the client ID and client secret (Refer to Client Key and Client Secret for Authentication) under the Master Label.
3. Click on `Edit Policies` and select `Relax IP restrictions` from the dropdown for IP Relaxation.

### Missing old events in "Login events table" panel

If **Login events table** does not display older documents after upgrading to version `0.8.0` or later, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the `login_rest` data stream.

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

The `setupaudittrail` data stream captures and records changes made by users in the organization's Setup area over the past 180 days.

{{event "setupaudittrail"}}

{{fields "setupaudittrail"}}
