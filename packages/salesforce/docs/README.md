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

### Finding Your Salesforce Instance Version

You can determine your Salesforce instance version using one of the following methods:

#### Method 1: Salesforce Classic

1. Navigate to the Home tab in Salesforce Classic.
2. Look for a link in the top right corner of the screen, such as `Summer '22`.
3. This link indicates the current release version of your Salesforce instance.

#### Method 2: Using the Salesforce Instance URL

1. Use your Salesforce Instance URL with the following format:
   `(Salesforce Instance URL)/services/data`
2. Example: `https://na9.salesforce.com/services/data`

This will return an XML response listing available API versions. For example:

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

The last entry in the list indicates the current release version of your Salesforce instance. In the example above, the version is `Summer '22 (v55.0)`.

## Prerequisites

To use this integration, you need Elasticsearch for storing and searching your data, and Kibana for visualizing and managing it. We recommend using our hosted Elasticsearch Service on Elastic Cloud, but you can also self-manage the Elastic Stack on your own hardware.

### Enabling API Access in Salesforce

Ensure that the `API Enabled` permission is selected for the user profile in your Salesforce instance. Follow these steps to enable it:

1. Navigate to `Setup` > `Quick Find` > `Users`, and click on `Users`.
2. Click on the profile link associated with the `User Account` used for data collection.
3. Search for the `API Enabled` permission on the profile page. If it’s not present, search under `System Permissions` and check if the `API Enabled` privilege is selected. If not, enable it for data collection.

### Collecting Data Using Real-Time Event Monitoring API

To enable data collection using the [Real-Time Event Monitoring API](https://help.salesforce.com/s/articleView?id=sf.real_time_event_monitoring_enable.htm&type=5):

1. Navigate to `Setup` > `Quick Find` > `Event Manager`.
2. Click on "Event Manager".
3. For each event type you want to monitor (e.g., Login Event, Logout Event), click the dropdown arrow and select "Enable Storage".
4. Ensure you have the necessary permissions: "View Real-Time Event Monitoring Data" and "Use Real-Time Event Monitoring APIs".

> Note: Real-Time Event Monitoring may require additional licensing. Check with your Salesforce account representative if you're unsure about your subscription level.

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

If **Login events table** does not display older documents after upgrading to version `0.8.0` or later, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the `login` data stream.

## Logs reference

### Apex

The `apex` data stream captures events related to Apex operations, enabling developers to access the Salesforce platform back-end database and client-server interfaces to create third-party SaaS applications.

An example event for `apex` looks as following:

```json
{
    "@timestamp": "2022-11-22T04:46:15.591Z",
    "agent": {
        "ephemeral_id": "bcd82746-7d4f-4c15-8288-e159f8223e86",
        "id": "ea40bcb3-cd35-4db9-b0d3-81d94e75b64d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.0"
    },
    "data_stream": {
        "dataset": "salesforce.apex",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ea40bcb3-cd35-4db9-b0d3-81d94e75b64d",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "action": "apex-callout",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "salesforce.apex",
        "duration": 1293,
        "ingested": "2024-06-21T16:36:07Z",
        "kind": "event",
        "original": "{\"CLIENT_IP\":\"81.2.69.142\",\"CPU_TIME\":\"10\",\"EVENT_TYPE\":\"ApexCallout\",\"LOGIN_KEY\":\"Obv9123BzbaxqCo1\",\"METHOD\":\"GET\",\"ORGANIZATION_ID\":\"00D5j000000001V\",\"REQUEST_ID\":\"4exLFFQZ1234xFl1cJNwOV\",\"REQUEST_SIZE\":\"10\",\"RESPONSE_SIZE\":\"256\",\"RUN_TIME\":\"1305\",\"SESSION_KEY\":\"WvtsJ1235oW24EbH\",\"SUCCESS\":\"1\",\"TIME\":\"1293\",\"TIMESTAMP\":\"20221122044615.591\",\"TIMESTAMP_DERIVED\":\"2022-11-22T04:46:15.591Z\",\"TYPE\":\"OData\",\"URI\":\"CALLOUT-LOG\",\"URI_ID_DERIVED\":\"0055j000000utlPAQZB\",\"URL\":\"https://temp.sh/odata/Accounts\",\"USER_ID\":\"0055j0000000001\",\"USER_ID_DERIVED\":\"0055j012345utlPAAQ\"}",
        "outcome": "success",
        "provider": "EventLogFile",
        "type": [
            "connection"
        ],
        "url": "https://temp.sh/odata/Accounts"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "345c85cf1fe945e2b19719b370c09a48",
        "ip": [
            "192.168.251.7"
        ],
        "mac": [
            "02-42-C0-A8-FB-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.114.2.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "http": {
        "request": {
            "bytes": 10,
            "method": "GET"
        },
        "response": {
            "bytes": 256
        }
    },
    "input": {
        "type": "salesforce"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "salesforce": {
        "apex": {
            "cpu_time": 10,
            "event_type": "ApexCallout",
            "login_key": "Obv9123BzbaxqCo1",
            "organization_id": "00D5j000000001V",
            "request_id": "4exLFFQZ1234xFl1cJNwOV",
            "run_time": 1305,
            "type": "OData",
            "uri": "CALLOUT-LOG",
            "uri_derived_id": "0055j000000utlPAQZB",
            "user_id_derived": "0055j012345utlPAAQ"
        },
        "instance_url": "http://elastic-package-service-salesforce-1:8010"
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "salesforce-apex"
    ],
    "user": {
        "id": "0055j0000000001"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| input.type | Input type. | keyword |  |  |
| salesforce.apex.action | Action performed by the callout. | keyword |  |  |
| salesforce.apex.callout_time | Time spent waiting on web service callouts, in milliseconds. | float | ms | gauge |
| salesforce.apex.class_name | The Apex class name. If the class is part of a managed package, this string includes the package namespace. | keyword |  |  |
| salesforce.apex.client_name | The name of the client that's using Salesforce services. This field is an optional parameter that can be passed in API calls. If blank, the caller didn't specify a client in the CallOptions header. | keyword |  |  |
| salesforce.apex.cpu_time | The CPU time in milliseconds used to complete the request. | float | ms | gauge |
| salesforce.apex.db_blocks | Indicates how much activity is occurring in the database. A high value for this field suggests that adding indexes or filters on your queries would benefit performance. | long |  | gauge |
| salesforce.apex.db_cpu_time | The CPU time in milliseconds to complete the request. Indicates the amount of activity taking place in the database layer during the request. | float | ms | gauge |
| salesforce.apex.db_total_time | Time (in milliseconds) spent waiting for database processing in aggregate for all operations in the request. Compare this field to cpu_time to determine whether performance issues are occurring in the database layer or in your own code. | float | ms | gauge |
| salesforce.apex.entity | Name of the external object being accessed. | keyword |  |  |
| salesforce.apex.entity_name | The name of the object affected by the trigger. | keyword |  |  |
| salesforce.apex.entry_point | The entry point for this Apex execution. | keyword |  |  |
| salesforce.apex.event_type | The type of event. | keyword |  |  |
| salesforce.apex.execute_ms | How long it took (in milliseconds) for Salesforce to prepare and execute the query. Available in API version 42.0 and later. | float | ms | gauge |
| salesforce.apex.fetch_ms | How long it took (in milliseconds) to retrieve the query results from the external system. Available in API version 42.0 and later. | float | ms | gauge |
| salesforce.apex.fields_count | The number of fields or columns, where applicable. | long |  |  |
| salesforce.apex.filter | Field expressions to filter which rows to return. Corresponds to WHERE in SOQL queries. | keyword |  |  |
| salesforce.apex.is_long_running_request | Indicates whether the request is counted against your org's concurrent long-running Apex request limit. | boolean |  |  |
| salesforce.apex.limit | Maximum number of rows to return for a query. Corresponds to LIMIT in SOQL queries. | long |  |  |
| salesforce.apex.limit_usage_pct | The percentage of Apex SOAP calls that were made against the organization's limit. | float | percent | gauge |
| salesforce.apex.login_key | The string that ties together all events in a given user's login session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |  |  |
| salesforce.apex.media_type | The media type of the response. | keyword |  |  |
| salesforce.apex.message | Error or warning message associated with the failed call. | text |  |  |
| salesforce.apex.method_name | The name of the calling Apex method. | keyword |  |  |
| salesforce.apex.offset | Number of rows to skip when paging through a result set. Corresponds to OFFSET in SOQL queries. | long |  |  |
| salesforce.apex.orderby | Field or column to use for sorting query results, and whether to sort the results in ascending (default) or descending order. Corresponds to ORDER BY in SOQL queries. | keyword |  |  |
| salesforce.apex.organization_id | The 15-character ID of the organization. | keyword |  |  |
| salesforce.apex.query | The SOQL query, if one was performed. | keyword |  |  |
| salesforce.apex.quiddity | The type of outer execution associated with this event. | keyword |  |  |
| salesforce.apex.request_id | The unique ID of a single transaction. A transaction can contain one or more events. Each event in a given transaction has the same request_id. | keyword |  |  |
| salesforce.apex.request_status | The status of the request for a page view or user interface action. | keyword |  |  |
| salesforce.apex.rows_fetched | Number of rows fetched by the callout. Available in API version 42.0 and later. | long |  |  |
| salesforce.apex.rows_processed | The number of rows that were processed in the request. | long |  |  |
| salesforce.apex.rows_total | Total number of records in the result set. The value is always -1 if the custom adapter's DataSource.Provider class doesn't declare the QUERY_TOTAL_SIZE capability. | long |  |  |
| salesforce.apex.run_time | The amount of time that the request took in milliseconds. | float | ms | gauge |
| salesforce.apex.select | Comma-separated list of fields being queried. Corresponds to SELECT in SOQL queries. | keyword |  |  |
| salesforce.apex.soql_queries_count | The number of SOQL queries that were executed during the event. | long |  |  |
| salesforce.apex.subqueries | Reserved for future use. | keyword |  |  |
| salesforce.apex.throughput | Number of records retrieved in one second. | float |  | gauge |
| salesforce.apex.trigger_id | The 15-character ID of the trigger that was fired. | keyword |  |  |
| salesforce.apex.trigger_name | For triggers coming from managed packages, trigger_name includes a namespace prefix separated with a dot (.) character. If no namespace prefix is present, the trigger is from an unmanaged trigger. | keyword |  |  |
| salesforce.apex.trigger_type | The type of this trigger. | keyword |  |  |
| salesforce.apex.type | The type of Apex callout. | keyword |  |  |
| salesforce.apex.uri | The URI of the page that's receiving the request. | keyword |  |  |
| salesforce.apex.uri_derived_id | The 18-character case-safe ID of the URI of the page that's receiving the request. | keyword |  |  |
| salesforce.apex.user_agent | The numeric code for the type of client used to make the request (for example, the browser, application, or API). | keyword |  |  |
| salesforce.apex.user_id_derived | The 18-character case-safe ID of the user who's using Salesforce services through the UI or the API. | keyword |  |  |
| salesforce.instance_url | The Salesforce instance URL. | keyword |  |  |


### Login

The `login` data stream captures events that detail the login history of users within your Salesforce organization. This data stream provides insights into user authentication activities, helping you monitor and analyze login patterns, detect anomalies, and ensure security compliance.

An example event for `login` looks as following:

```json
{
    "@timestamp": "2022-11-22T04:46:15.591Z",
    "agent": {
        "ephemeral_id": "b02f2751-9a38-4438-8b75-937262b340bc",
        "id": "ea40bcb3-cd35-4db9-b0d3-81d94e75b64d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.0"
    },
    "data_stream": {
        "dataset": "salesforce.login",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ea40bcb3-cd35-4db9-b0d3-81d94e75b64d",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "action": "login-attempt",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "salesforce.login",
        "ingested": "2024-06-21T16:46:09Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"API_TYPE\":\"f\",\"API_VERSION\":\"9998.0\",\"AUTHENTICATION_METHOD_REFERENCE\":\"\",\"BROWSER_TYPE\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36\",\"CIPHER_SUITE\":\"ECDHE-RSA-AES256-GCM-SHA384\",\"CLIENT_IP\":\"81.2.69.142\",\"CPU_TIME\":\"30\",\"DB_TOTAL_TIME\":\"52435102\",\"EVENT_TYPE\":\"Login\",\"LOGIN_KEY\":\"QfNecrLXSII6fsBq\",\"LOGIN_STATUS\":\"LOGIN_NO_ERROR\",\"ORGANIZATION_ID\":\"00D5j000000VI3n\",\"REQUEST_ID\":\"4ehU_U-nbQyAPFl1cJILm-\",\"REQUEST_STATUS\":\"Success\",\"RUN_TIME\":\"83\",\"SESSION_KEY\":\"\",\"SOURCE_IP\":\"81.2.69.142\",\"TIMESTAMP\":\"20221122044615.591\",\"TIMESTAMP_DERIVED\":\"2022-11-22T04:46:15.591Z\",\"TLS_PROTOCOL\":\"TLSv1.2\",\"URI\":\"/index.jsp\",\"URI_ID_DERIVED\":\"s4heK3WbH-lcJIL3-n\",\"USER_ID\":\"0055j000000utlP\",\"USER_ID_DERIVED\":\"0055j000000utlPAAQ\",\"USER_NAME\":\"user@elastic.co\",\"USER_TYPE\":\"Standard\"}",
        "outcome": "success",
        "provider": "EventLogFile",
        "type": [
            "info"
        ],
        "url": "/index.jsp"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "345c85cf1fe945e2b19719b370c09a48",
        "ip": [
            "192.168.251.7"
        ],
        "mac": [
            "02-42-C0-A8-FB-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.114.2.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "salesforce"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "salesforce": {
        "instance_url": "http://elastic-package-service-salesforce-1:8010",
        "login": {
            "api": {
                "type": "Feed",
                "version": "9998.0"
            },
            "client": {
                "ip": "81.2.69.142"
            },
            "cpu_time": 30,
            "db_total_time": 52435102,
            "event_type": "Login",
            "key": "QfNecrLXSII6fsBq",
            "organization_id": "00D5j000000VI3n",
            "request": {
                "id": "4ehU_U-nbQyAPFl1cJILm-",
                "status": "Success"
            },
            "run_time": 83,
            "uri": {
                "id": "s4heK3WbH-lcJIL3-n"
            },
            "user_id": "0055j000000utlP"
        }
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "salesforce-login"
    ],
    "tls": {
        "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "version": "1.2",
        "version_protocol": "TLS"
    },
    "user": {
        "email": "user@elastic.co",
        "id": "0055j000000utlPAAQ",
        "roles": [
            "Standard"
        ]
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Chrome",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| input.type | Input type. | keyword |  |  |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |  |  |
| salesforce.login.additional_info | Additional information that's captured from the HTTP headers during a login request. | match_only_text |  |  |
| salesforce.login.api.type | The type of Salesforce API request. | keyword |  |  |
| salesforce.login.api.version | The version of the Salesforce API used for the login request. | keyword |  |  |
| salesforce.login.application | The application used to access the Salesforce organization. | keyword |  |  |
| salesforce.login.auth.method_reference | The authentication method reference used by a third-party identity provider for SSO using the OpenID Connect protocol. This field is available in API version 51.0 and later. | keyword |  |  |
| salesforce.login.auth.service_id | The authentication service ID used by a third-party identity provider for single sign-on (SSO) using the OpenID Connect protocol. | keyword |  |  |
| salesforce.login.client.ip | The IP address of the client using Salesforce services. Internal Salesforce IP addresses are shown as "Salesforce.com IP". | ip |  |  |
| salesforce.login.client_version | The version of the client used for the login request. | keyword |  |  |
| salesforce.login.cpu_time | The CPU time in milliseconds used to complete the login request, indicating the amount of activity in the application server layer. | long | ms | gauge |
| salesforce.login.db_total_time | The time in nanoseconds for the database round trip during login, including time spent in the JDBC driver, network, and database CPU time. | long | nanos | gauge |
| salesforce.login.evaluation_time | The amount of time it took to evaluate the transaction security policy, in milliseconds. This field is available in API version 46.0 and later. | double | ms | gauge |
| salesforce.login.event_type | The type of event. For login events, the value is always "Login". | keyword |  |  |
| salesforce.login.geo_id | The Salesforce ID of the LoginGeo object associated with the user's IP address during login. | keyword |  |  |
| salesforce.login.history_id | The identifier that tracks a user session, allowing correlation of user activity with a specific login instance. | keyword |  |  |
| salesforce.login.key | The string that ties together all events in a given user's login session, starting with the login event and ending with either a logout event or the user session expiring. | keyword |  |  |
| salesforce.login.organization_id | The 15-character ID of the Salesforce organization. | keyword |  |  |
| salesforce.login.related_event_identifier | The identifier of a related event associated with the login event. | keyword |  |  |
| salesforce.login.request.id | The unique identifier for the login request transaction. | keyword |  |  |
| salesforce.login.request.status | The status of the login request (e.g., Success, Failed). | keyword |  |  |
| salesforce.login.run_time | The total time in milliseconds taken by the login request. | long | ms | gauge |
| salesforce.login.transaction_security.policy.id | The ID of the transaction security policy used to evaluate the login event. | keyword |  |  |
| salesforce.login.transaction_security.policy.outcome | The outcome of the transaction security policy evaluation (e.g., Block, Notified, NoAction). | keyword |  |  |
| salesforce.login.type | The type of login used to access the session. | keyword |  |  |
| salesforce.login.uri.id | The 18-character case-insensitive ID of the URI of the page receiving the login request. | keyword |  |  |
| salesforce.login.user_id | The 15-character ID of the user logging in to Salesforce. | keyword |  |  |


### Logout

The `logout` data stream captures events that detail the logout history of users within your Salesforce organization. This data stream provides insights into user authentication activities, helping you monitor and analyze logout patterns, detect anomalies, and ensure security compliance.

An example event for `logout` looks as following:

```json
{
    "@timestamp": "2022-11-22T07:37:25.779Z",
    "agent": {
        "ephemeral_id": "222f4fde-1141-42af-adaf-4b86e6aa9c18",
        "id": "ea40bcb3-cd35-4db9-b0d3-81d94e75b64d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.0"
    },
    "data_stream": {
        "dataset": "salesforce.logout",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ea40bcb3-cd35-4db9-b0d3-81d94e75b64d",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "action": "logout",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "code": "4exLFFQZ1234xFl1cJNwOV",
        "dataset": "salesforce.logout",
        "ingested": "2024-06-21T16:47:21Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"API_TYPE\":\"f\",\"API_VERSION\":\"54.0\",\"APP_TYPE\":\"1000\",\"BROWSER_TYPE\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36\",\"CLIENT_IP\":\"81.2.69.142\",\"CLIENT_VERSION\":\"9998\",\"EVENT_TYPE\":\"Logout\",\"LOGIN_KEY\":\"Obv9123BzbaxqCo1\",\"ORGANIZATION_ID\":\"00D5j001234VI3n\",\"PLATFORM_TYPE\":\"1015\",\"REQUEST_ID\":\"4exLFFQZ1234xFl1cJNwOV\",\"RESOLUTION_TYPE\":\"9999\",\"SESSION_KEY\":\"WvtsJ1235oW24EbH\",\"SESSION_LEVEL\":\"1\",\"SESSION_TYPE\":\"O\",\"TIMESTAMP\":\"20221122073725.779\",\"TIMESTAMP_DERIVED\":\"2022-11-22T07:37:25.779Z\",\"USER_ID\":\"0055j000000utlP\",\"USER_ID_DERIVED\":\"0055j000000utlPAAQ\",\"USER_INITIATED_LOGOUT\":\"0\",\"USER_TYPE\":\"S\"}",
        "provider": "EventLogFile",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "345c85cf1fe945e2b19719b370c09a48",
        "ip": [
            "192.168.251.7"
        ],
        "mac": [
            "02-42-C0-A8-FB-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.114.2.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "salesforce"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "salesforce": {
        "instance_url": "http://elastic-package-service-salesforce-1:8010",
        "logout": {
            "api": {
                "type": "Feed",
                "version": "54.0"
            },
            "app_type": "Application",
            "browser_type": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
            "client_version": "9998",
            "event_type": "Logout",
            "login_key": "Obv9123BzbaxqCo1",
            "organization_id": "00D5j001234VI3n",
            "platform_type": "Windows 10",
            "resolution_type": "9999",
            "session": {
                "level": "Standard Session",
                "type": "Oauth2"
            },
            "user": {
                "roles": [
                    "Standard"
                ]
            },
            "user_id": "0055j000000utlP",
            "user_initiated_logout": "0"
        }
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "salesforce-logout"
    ],
    "user": {
        "id": "0055j000000utlPAAQ"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type. | keyword |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |
| salesforce.logout.api.type | The type of Salesforce API request. | keyword |
| salesforce.logout.api.version | The version of the Salesforce API that's being used. | keyword |
| salesforce.logout.app_type | The application type that was in use upon logging out. | keyword |
| salesforce.logout.browser_type | The identifier string returned by the browser used at login. | keyword |
| salesforce.logout.client_version | The version of the client that was in use upon logging out. | keyword |
| salesforce.logout.event_identifier | This field is populated only when the activity that this event monitors requires extra authentication, such as multi-factor authentication. In this case, Salesforce generates more events and sets the RelatedEventIdentifier field of the new events to the value of the EventIdentifier field of the original event. Use this field with the EventIdentifier field to correlate all the related events. If no extra authentication is required, this field is blank. | keyword |
| salesforce.logout.event_type | The type of event. The value is always Logout. | keyword |
| salesforce.logout.login_key | The string that ties together all events in a given user's login session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |
| salesforce.logout.organization_id | The 15-character ID of the organization. | keyword |
| salesforce.logout.platform_type | The code for the client platform. If a timeout caused the logout, this field is null. | keyword |
| salesforce.logout.resolution_type | The screen resolution of the client. If a timeout caused the logout, this field is null. | keyword |
| salesforce.logout.session.key | The user's unique session ID. You can use this value to identify all user events within a session. When a user logs out and logs in again, a new session is started. | keyword |
| salesforce.logout.session.level | The security level of the session that was used when logging out (e.g. Standard Session or High-Assurance Session). | keyword |
| salesforce.logout.session.type | The session type that was used when logging out (e.g. API, Oauth2 or UI). | keyword |
| salesforce.logout.user.roles | The roles of the user who's using Salesforce services through the UI or the API. | keyword |
| salesforce.logout.user_id | The 15-character ID of the user who's using Salesforce services through the UI or the API. | keyword |
| salesforce.logout.user_id_derived | The 18-character case-safe ID of the user who's using Salesforce services through the UI or the API. | keyword |
| salesforce.logout.user_initiated_logout | The value is 1 if the user intentionally logged out of the organization by clicking the Logout button. If the user's session timed out due to inactivity or another implicit logout action, the value is 0. | keyword |


### SetupAuditTrail

The `setupaudittrail` data stream captures and records changes made by users in the organization's Setup area over the past 180 days.

An example event for `setupaudittrail` looks as following:

```json
{
    "@timestamp": "2022-08-16T09:26:38.000Z",
    "agent": {
        "ephemeral_id": "8a1bedda-17d6-4895-b914-851f067b9106",
        "id": "ea40bcb3-cd35-4db9-b0d3-81d94e75b64d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.0"
    },
    "data_stream": {
        "dataset": "salesforce.setupaudittrail",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ea40bcb3-cd35-4db9-b0d3-81d94e75b64d",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "action": "insertConnectedApplication",
        "agent_id_status": "verified",
        "created": "2022-08-16T09:26:38.000Z",
        "dataset": "salesforce.setupaudittrail",
        "id": "0Ym5j000019nwonCAA",
        "ingested": "2024-06-21T16:40:13Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"Action\":\"insertConnectedApplication\",\"CreatedByContext\":\"Einstein\",\"CreatedById\":\"0055j000000utlPAAQ\",\"CreatedDate\":\"2022-08-16T09:26:38.000+0000\",\"DelegateUser\":\"user1\",\"Display\":\"For user user@elastic.co, the User Verified Email status changed to verified\",\"Id\":\"0Ym5j000019nwonCAA\",\"Section\":\"Connected Apps\"}",
        "provider": "Object",
        "type": [
            "admin"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "345c85cf1fe945e2b19719b370c09a48",
        "ip": [
            "192.168.251.7"
        ],
        "mac": [
            "02-42-C0-A8-FB-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.114.2.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "salesforce"
    },
    "salesforce": {
        "instance_url": "http://elastic-package-service-salesforce-1:8010",
        "setup_audit_trail": {
            "created_by_context": "Einstein",
            "created_by_id": "0055j000000utlPAAQ",
            "delegate_user": "user1",
            "display": "For user user@elastic.co, the User Verified Email status changed to verified",
            "section": "Connected Apps"
        }
    },
    "tags": [
        "preserve_original_event",
        "salesforce-setupaudittrail"
    ],
    "user": {
        "id": "0055j000000utlPAAQ",
        "name": "user@elastic.co"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type. | keyword |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |
| salesforce.setup_audit_trail.created_by_context | The context under which the Setup change was made. For example, if Einstein uses cloud-to-cloud services to make a change in Setup, the value of this field is Einstein. | keyword |
| salesforce.setup_audit_trail.created_by_id | The id under which the Setup change was made. For example, if Einstein uses cloud-to-cloud services to make a change in Setup, the value of this field is id of Einstein. | keyword |
| salesforce.setup_audit_trail.created_by_issuer | Reserved for future use. | keyword |
| salesforce.setup_audit_trail.delegate_user | The Login-As user who executed the action in Setup. If a Login-As user didn't perform the action, this field is blank. This field is available in API version 35.0 and later. | keyword |
| salesforce.setup_audit_trail.display | The full description of changes made in Setup. For example, if the Action field has a value of PermSetCreate, the Display field has a value like “Created permission set MAD: with user license Salesforce." | keyword |
| salesforce.setup_audit_trail.responsible_namespace_prefix | Unknown | keyword |
| salesforce.setup_audit_trail.section | The section in the Setup menu where the action occurred. For example, Manage Users or Company Profile. | keyword |

