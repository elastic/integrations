# Salesforce Integration

## Overview

The Salesforce integration allows users to monitor a [Salesforce](https://www.salesforce.com/) instance. Salesforce is a customer relationship management (CRM) platform. It provides an ecosystem for businesses to manage marketing, sales, commerce, service, and IT teams from anywhere with one integrated CRM platform.

Use the Salesforce integration to:
- Gain insights into login and other operational activities by the users of the organization.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

As an example, users can use the data from this integration to understand the activity patterns of users based on region or the distribution of users by license type. 

## Data streams

The Salesforce integration collects log events using the REST API and Streaming API of Salesforce.

**Logs** help users to keep a record of events happening in Salesforce.
Log data streams collected by the Salesforce integration include [Login REST](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_login.htm), [Login Stream](https://developer.salesforce.com/docs/atlas.en-us.236.0.platform_events.meta/platform_events/sforce_api_objects_logineventstream.htm), [Logout REST](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_logout.htm), [Logout Stream](https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_logouteventstream.htm), [Apex](https://developer.salesforce.com/docs/atlas.en-us.238.0.object_reference.meta/object_reference/sforce_api_objects_apexclass.htm), and [SetupAuditTrail](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_setupaudittrail.htm).

Data streams:
- `login_rest` and `login_stream`: Tracks login activity of users who log in to Salesforce.
- `logout_rest` and `logout_stream`: Tracks logout activity of users who logout from Salesforce.
- `apex`: Represents information about various Apex events like Callout, Execution, REST API, SOAP API, Trigger, etc.
- `setupaudittrail`: Represents changes users made in the user's organization's Setup area for at least the last 180 days.

## Compatibility

This integration has been tested against Salesforce `Spring '22 (v54.0) release`.

In order to find out the Salesforce version of the user's instance, see below:

1. On the Home tab in Salesforce Classic, in the top right corner of the screen is a link to releases like `Summer '22`. This indicates the release version of the salesforce instance.

2. An alternative way to find out the version of Salesforce is by hitting the following URL:
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

## Prerequisites

Users need Elasticsearch for storing and searching their data and Kibana for visualizing and managing it.
Users can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on their own hardware.

In the user's Salesforce instance, ensure that `API Enabled permission` is selected for the user profile. Follow the below steps to enable the same:

1. Go to `Setup` > `Quick Find` > `Users`, and Click on `Users`.
2. Click on the profile link associated with the `User Account` used for data collection.
3. Search for `API Enabled` permission on the same page. In case it’s not present, search it under `System Permissions` and check if `API Enabled` privilege is selected. If not, enable it for data collection.

For collecting data using `Streaming API`:

In the user's Salesforce instance, ensure that `View Real-Time Event Monitoring Data` is selected for the user profile. Follow the below steps to enable the same:

1. Go to `Setup` > `Quick Find` > `Users`, and Click on `Users`.
2. Click on the profile link associated with the `User Account` used for data collection.
3. Search for `View Real-Time Event Monitoring Data` permission on the same page. In case it’s not present, search it under `System Permissions` and check if `View Real-Time Event Monitoring Data` privilege is selected. If not, enable it for data collection.

Also, ensure that `Event Streaming` is enabled for `Login Event` and `Logout Event`. Follow the below steps to enable the same: 

1. Go to `Setup` > `Quick Find` > `Event Manager`, and Click on `Event Manager`.
2. For `Login Event` and `Logout Event` click on the down arrow button on the left corner and select `Enable Streaming`.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

Note: Please enable either `login_rest` / `login_stream` data stream and either `logout_rest` / `logout_stream` data stream to avoid data duplication.

## Configuration

Users need the following information from the user's Salesforce instance to configure this integration in Elastic:

### Salesforce Instance URL

The instance the user's Salesforce Organization uses is indicated in the URL of the address bar in Salesforce Classic. The value before 'salesforce.com' is the user's Salesforce Instance.

Example URL: `https://na9.salesforce.com/home/home.jsp`

In the above example, the value before 'salesforce.com' is the user's Salesforce Instance. In this example, the Salesforce Organization is located on NA9. 

The Salesforce Instance URL is: `https://na9.salesforce.com`

In Salesforce Lightning, it is available under the user name in the “View Profile” tab.

### Client Key and Client Secret for Authentication

In order to use this integration, users need to create a new Salesforce Application using OAuth. Follow the steps below to create a connected application in Salesforce:

1. Login to [Salesforce](https://login.salesforce.com/) with the same user credentials that the user wants to collect data with.
2. Click on Setup on the top right menu bar. On the Setup page search `App Manager` in the `Search Setup` search box at the top of the page, then select `App Manager`.
3. Click *New Connected App*.
4. Provide a name for the connected application. This will be displayed in the App Manager and on its App Launcher tile. 
5. Enter the API name. The default is a version of the name without spaces. Only letters, numbers, and underscores are allowed. If the original app name contains any other characters, edit the default name.
6. Enter the contact email for Salesforce.
7. Under the API (Enable OAuth Settings) section of the page, select *Enable OAuth Settings*.
8. In the Callback URL enter the Instance URL (Please refer to `Salesforce Instance URL`)
9. Select the following OAuth scopes to apply to the connected app:
    - Manage user data via APIs (api). 
    - Perform requests at any time (refresh_token, offline_access).
    - (Optional) In case of data collection, if any permission issues arise, add the Full access (full) scope.
10. Select *Require Secret for the Web Server Flow* to require the app's client secret in exchange for an access token.
11. Select *Require Secret for Refresh Token Flow* to require the app's client secret in the authorization request of a refresh token and hybrid refresh token flow.
12. Click Save. It may take approximately 10 minutes for the changes to take effect.
13. Click Continue and then under API details click Manage Consumer Details, Verify the user account using Verification Code.
14. Copy `Consumer Key` and `Consumer Secret` from the Consumer Details section, which should be populated as value to Client ID and Client Secret respectively in the configuration.

For more details on how to Create a Connected App refer to the salesforce documentation [here](https://help.salesforce.com/apex/HTViewHelpDoc?id=connected_app_create.htm).

### Username

User Id of the registered user in Salesforce.

### Password

Password used for authenticating the above user.

## Additional Information

Follow the steps below, in case the user needs to find the API version:

1. Go to `Setup` > `Quick Find` > `Apex Classes`.
2. Click the `New` button.
3. Click the `Version Settings` tab.
4. Refer to the `Version` dropdown for the API Version number.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Salesforce Integration should display a list of available dashboards. Click on the dashboard available for the user's configured datastream. It should be populated with the required data.

## Troubleshooting

### Request timeout

In `Apex`, `Login Rest`, `Logout Rest`, or `SetupAuditTrail` datastreams, if the response is getting delayed from the Salesforce server side due to any reason then the following error might occur:
```
Error while processing http request: failed to execute rf.collectResponse: failed to execute http client.Do: failed to execute http client.Do: failed to read http.response.body
```
In this case, consider increasing `Request timeout` configuration from `Advanced options` section of that data stream.

### Data ingestion error

In case of data ingestion if the user finds the following type of error logs:
```
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
Please check if the `API Enabled permission` is provided to the `profile` associated with the `username` used as part of the integration.
Please refer to the Prerequisites section above for more information.

If the error continues follow these steps:

1. Go to `Setup` > `Quick Find` > `Manage Connected Apps`.
2. Click on the Connected App name created by the user to generate the client id and client secret (Refer to Client Key and Client Secret for Authentication) under the Master Label.
3. Click on Edit Policies, and select `Relax IP restrictions` from the dropdown for IP Relaxation.

### Missing old events in **Login events table** panel

If **Login events table** does not display older documents after upgrading to ``0.8.0`` or later versions, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``login_rest`` data stream.

## Logs reference

### Apex

This is the `apex` data stream. Apex enables developers to access the Salesforce platform back-end database and client-server interfaces to create third-party SaaS applications.

{{event "apex"}}

{{fields "apex"}}

### Login Rest

This is the `login_rest` data stream. It represents events containing details about the user's organization's login history.

{{event "login_rest"}}

{{fields "login_rest"}}

### Login Stream

This is the `login_stream` data stream. It represents events containing details about the user's organization's login history.

{{event "login_stream"}}

{{fields "login_stream"}}

### Logout Rest

This is the `logout_rest` data stream. It represents events containing details about the user's organization's logout history.

{{event "logout_rest"}}

{{fields "logout_rest"}}

### Logout Stream

This is the `logout_stream` data stream. It represents events containing details about the user's organization's logout history.

{{event "logout_stream"}}

{{fields "logout_stream"}}

### SetupAuditTrail

This is the `setupaudittrail` data stream. It represents changes users made in the user's organization's Setup area for at least the last 180 days.

{{event "setupaudittrail"}}

{{fields "setupaudittrail"}}
