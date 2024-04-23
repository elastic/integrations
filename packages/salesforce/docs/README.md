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

An example event for `apex` looks as following:

```json
{
    "@timestamp": "2022-11-22T04:46:15.591Z",
    "agent": {
        "ephemeral_id": "c50ecba0-45f3-4a29-bd66-d5bd6317345e",
        "id": "6e72b9f7-fadd-4789-a6ea-e17925d36c7e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "data_stream": {
        "dataset": "salesforce.apex",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "6e72b9f7-fadd-4789-a6ea-e17925d36c7e",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "action": "apex-callout",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2023-01-04T05:20:36.070Z",
        "dataset": "salesforce.apex",
        "duration": 1293,
        "ingested": "2023-01-04T05:20:38Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"CLIENT_IP\":\"81.2.69.142\",\"CPU_TIME\":\"10\",\"EVENT_TYPE\":\"ApexCallout\",\"LOGIN_KEY\":\"Obv9123BzbaxqCo1\",\"METHOD\":\"GET\",\"ORGANIZATION_ID\":\"00D5j000000001V\",\"REQUEST_ID\":\"4exLFFQZ1234xFl1cJNwOV\",\"REQUEST_SIZE\":\"10\",\"RESPONSE_SIZE\":\"256\",\"RUN_TIME\":\"1305\",\"SESSION_KEY\":\"WvtsJ1235oW24EbH\",\"SUCCESS\":\"1\",\"TIME\":\"1293\",\"TIMESTAMP\":\"20221122044615.591\",\"TIMESTAMP_DERIVED\":\"2022-11-22T04:46:15.591Z\",\"TYPE\":\"OData\",\"URI\":\"CALLOUT-LOG\",\"URI_ID_DERIVED\":\"0055j000000utlPAQZB\",\"URL\":\"https://temp.sh/odata/Accounts\",\"USER_ID\":\"0055j0000000001\",\"USER_ID_DERIVED\":\"0055j012345utlPAAQ\"}",
        "outcome": "success",
        "type": [
            "connection"
        ],
        "url": "https://temp.sh/odata/Accounts"
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
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "salesforce": {
        "apex": {
            "access_mode": "REST",
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
        "instance_url": "http://elastic-package-service_salesforce_1:8010"
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
        "salesforce-apex",
        "forwarded"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |  |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.duration | Duration of the event in milliseconds. If event.start and event.end are known this value should be the difference between the end and start time | long | ms |  |
| event.id | Unique ID to describe the event. | keyword |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |  |  |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |  |  |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |  |  |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |  |  |
| http.response.status_code | HTTP response status code. | long |  |  |
| input.type | Input type. | keyword |  |  |
| related.ip | All of the IPs seen on your event. | ip |  |  |
| salesforce.apex.access_mode | The mode of collecting logs from Salesforce - "REST" or "Stream". | keyword |  |  |
| salesforce.apex.action | Action performed by the callout. | keyword |  |  |
| salesforce.apex.callout_time | Time spent waiting on webservice callouts, in milliseconds. | float | ms | gauge |
| salesforce.apex.class_name | The Apex class name. If the class is part of a managed package, this string includes the package namespace. | keyword |  |  |
| salesforce.apex.client_name | The name of the client that's using Salesforce services. This field is an optional parameter that can be passed in API calls. If blank, the caller didnt specify a client in the CallOptions header. | keyword |  |  |
| salesforce.apex.cpu_time | The CPU time in milliseconds used to complete the request. | float | ms | gauge |
| salesforce.apex.db_blocks | Indicates how much activity is occurring in the database. A high value for this field suggests that adding indexes or filters on your queries would benefit performance. | long |  | gauge |
| salesforce.apex.db_cpu_time | The CPU time in milliseconds to complete the request. Indicates the amount of activity taking place in the database layer during the request. | float | ms | gauge |
| salesforce.apex.db_time.total | Time (in milliseconds) spent waiting for database processing in aggregate for all operations in the request. Compare this field to CPU_TIME to determine whether performance issues are occurring in the database layer or in your own code. | float | ms | gauge |
| salesforce.apex.entity | Name of the external object being accessed. | keyword |  |  |
| salesforce.apex.entity_name | The name of the object affected by the trigger. | keyword |  |  |
| salesforce.apex.entry_point | The entry point for this Apex execution. | keyword |  |  |
| salesforce.apex.event_type | The type of event. | keyword |  |  |
| salesforce.apex.execute.ms | How long it took (in milliseconds) for Salesforce to prepare and execute the query. Available in API version 42.0 and later. | float | ms | gauge |
| salesforce.apex.fetch.ms | How long it took (in milliseconds) to retrieve the query results from the external system. Available in API version 42.0 and later. | float | ms | gauge |
| salesforce.apex.fields.count | The number of fields or columns, where applicable. | long |  |  |
| salesforce.apex.filter | Field expressions to filter which rows to return. Corresponds to WHERE in SOQL queries. | keyword |  |  |
| salesforce.apex.is_long_running_request | Indicates whether the request is counted against your org's concurrent long-running Apex request limit (true) or not (false). | keyword |  |  |
| salesforce.apex.limit | Maximum number of rows to return for a query. Corresponds to LIMIT in SOQL queries. | long |  |  |
| salesforce.apex.limit_usage.pct | The percentage of Apex SOAP calls that were made against the organization's limit. | float | percent | gauge |
| salesforce.apex.login_key | The string that ties together all events in a given user's login session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |  |  |
| salesforce.apex.media_type | The media type of the response. | keyword |  |  |
| salesforce.apex.message | Error or warning message associated with the failed call. | keyword |  |  |
| salesforce.apex.method_name | The name of the calling Apex method. | keyword |  |  |
| salesforce.apex.offset | Number of rows to skip when paging through a result set. Corresponds to OFFSET in SOQL queries. | long |  |  |
| salesforce.apex.organization_id | The 15-character ID of the organization. | keyword |  |  |
| salesforce.apex.query | The SOQL query, if one was performed. | keyword |  |  |
| salesforce.apex.quiddity | The type of outer execution associated with this event. | keyword |  |  |
| salesforce.apex.request_id | The unique ID of a single transaction. A transaction can contain one or more events. Each event in a given transaction has the same REQUEST_ID. | keyword |  |  |
| salesforce.apex.request_status | The status of the request for a page view or user interface action. | keyword |  |  |
| salesforce.apex.rows.fetched | Number of rows fetched by the callout. Available in API version 42.0 and later. | long |  |  |
| salesforce.apex.rows.processed | The number of rows that were processed in the request. | long |  |  |
| salesforce.apex.rows.total | Total number of records in the result set. The value is always -1 if the custom adapter's DataSource.Provider class doesn't declare the QUERY_TOTAL_SIZE capability. | long |  |  |
| salesforce.apex.run_time | The amount of time that the request took in milliseconds. | float | ms | gauge |
| salesforce.apex.select | Comma-separated list of fields being queried. Corresponds to SELECT in SOQL queries. | keyword |  |  |
| salesforce.apex.soql_queries.count | The number of SOQL queries that were executed during the event. | long |  |  |
| salesforce.apex.subqueries | Reserved for future use. | keyword |  |  |
| salesforce.apex.throughput | Number of records retrieved in one second. | float |  | gauge |
| salesforce.apex.trigger.id | The 15-character ID of the trigger that was fired. | keyword |  |  |
| salesforce.apex.trigger.name | For triggers coming from managed packages, TRIGGER_NAME includes a namespace prefix separated with a . character. If no namespace prefix is present, the trigger is from an unmanaged trigger. | keyword |  |  |
| salesforce.apex.trigger.type | The type of this trigger. | keyword |  |  |
| salesforce.apex.type | The type of Apex callout. | keyword |  |  |
| salesforce.apex.uri | The URI of the page that's receiving the request. | keyword |  |  |
| salesforce.apex.uri_derived_id | The 18-character case-safe ID of the URI of the page that's receiving the request. | keyword |  |  |
| salesforce.apex.user_agent | The numeric code for the type of client used to make the request (for example, the browser, application, or API). | keyword |  |  |
| salesforce.apex.user_id_derived | The 18-character case-safe ID of the user who's using Salesforce services through the UI or the API. | keyword |  |  |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |  |  |
| source.geo.city_name | City name. | keyword |  |  |
| source.geo.continent_name | Name of the continent. | keyword |  |  |
| source.geo.country_iso_code | Country ISO code. | keyword |  |  |
| source.geo.country_name | Country name. | keyword |  |  |
| source.geo.location | Longitude and latitude. | geo_point |  |  |
| source.geo.region_iso_code | Region ISO code. | keyword |  |  |
| source.geo.region_name | Region name. | keyword |  |  |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
| user.id | Unique identifier of the user. | keyword |  |  |
| user.name | Short name or login of the user. | keyword |  |  |
| user.name.text | Multi-field of `user.name`. | match_only_text |  |  |
| user.roles | Array of user roles at the time of the event. | keyword |  |  |


### Login Rest

This is the `login_rest` data stream. It represents events containing details about the user's organization's login history.

An example event for `login_rest` looks as following:

```json
{
    "@timestamp": "2022-11-22T04:46:15.591Z",
    "agent": {
        "ephemeral_id": "d3dbbcc8-b6d9-4663-aa98-297eafdb9870",
        "id": "aac3e549-38a7-4347-8467-9dff612f8103",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "salesforce.login_rest",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "aac3e549-38a7-4347-8467-9dff612f8103",
        "snapshot": false,
        "version": "8.5.0"
    },
    "event": {
        "action": "login-attempt",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2023-04-18T13:50:26.274Z",
        "dataset": "salesforce.login_rest",
        "ingested": "2023-04-18T13:50:27Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"API_TYPE\":\"f\",\"API_VERSION\":\"9998.0\",\"AUTHENTICATION_METHOD_REFERENCE\":\"\",\"BROWSER_TYPE\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36\",\"CIPHER_SUITE\":\"ECDHE-RSA-AES256-GCM-SHA384\",\"CLIENT_IP\":\"81.2.69.142\",\"CPU_TIME\":\"30\",\"DB_TOTAL_TIME\":\"52435102\",\"EVENT_TYPE\":\"Login\",\"LOGIN_KEY\":\"QfNecrLXSII6fsBq\",\"LOGIN_STATUS\":\"LOGIN_NO_ERROR\",\"ORGANIZATION_ID\":\"00D5j000000VI3n\",\"REQUEST_ID\":\"4ehU_U-nbQyAPFl1cJILm-\",\"REQUEST_STATUS\":\"Success\",\"RUN_TIME\":\"83\",\"SESSION_KEY\":\"\",\"SOURCE_IP\":\"81.2.69.142\",\"TIMESTAMP\":\"20221122044615.591\",\"TIMESTAMP_DERIVED\":\"2022-11-22T04:46:15.591Z\",\"TLS_PROTOCOL\":\"TLSv1.2\",\"URI\":\"/index.jsp\",\"URI_ID_DERIVED\":\"s4heK3WbH-lcJIL3-n\",\"USER_ID\":\"0055j000000utlP\",\"USER_ID_DERIVED\":\"0055j000000utlPAAQ\",\"USER_NAME\":\"user@elastic.co\",\"USER_TYPE\":\"Standard\"}",
        "outcome": "success",
        "type": [
            "info"
        ],
        "url": "/index.jsp"
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "salesforce": {
        "instance_url": "http://elastic-package-service_salesforce_1:8010",
        "login": {
            "access_mode": "REST",
            "api": {
                "type": "Feed",
                "version": "9998.0"
            },
            "client_ip": "81.2.69.142",
            "cpu_time": 30,
            "db_time": {
                "total": 52.435104
            },
            "document_id": "K7i/LrB3UIX55uwooXhvn+bfgs8=",
            "event_type": "Login",
            "key": "QfNecrLXSII6fsBq",
            "organization_id": "00D5j000000VI3n",
            "request_id": "4ehU_U-nbQyAPFl1cJILm-",
            "request_status": "Success",
            "run_time": 83,
            "uri_derived_id": "s4heK3WbH-lcJIL3-n",
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
        "salesforce-login_rest",
        "forwarded"
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
        "name": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |  |  |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |  |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |  |  |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |  |  |
| input.type | Input type. | keyword |  |  |
| related.ip | All of the IPs seen on your event. | ip |  |  |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |  |  |
| salesforce.login.access_mode | Mode of API from which the event is collected. | keyword |  |  |
| salesforce.login.api.type | The type of API request. | keyword |  |  |
| salesforce.login.api.version | The version of the API that's being used. | keyword |  |  |
| salesforce.login.auth.service_id | The authentication method used by a third-party identification provider for an OpenID Connect single sign-on protocol. | keyword |  |  |
| salesforce.login.client_ip | The IP address of the client that's using Salesforce services. | keyword |  |  |
| salesforce.login.cpu_time | The CPU time in milliseconds used to complete the request. This field indicates the amount of activity taking place in the app server layer. | float | ms | gauge |
| salesforce.login.db_time.total | The time in milliseconds for a database round trip. Includes time spent in the JDBC driver, network to the database, and db_time.total. Compare this field to cpu_time to determine whether performance issues are occurring in the database layer or in your own code. | float | ms | gauge |
| salesforce.login.document_id | Unique document id generated by Elasticsearch. | keyword |  |  |
| salesforce.login.event_type | The type of event. The value is always Login. | keyword |  |  |
| salesforce.login.key | The string that ties together all events in a given user's login session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |  |  |
| salesforce.login.organization_id | The 15-character ID of the organization. | keyword |  |  |
| salesforce.login.request_id | The unique ID of a single transaction. A transaction can contain one or more events. Each event in a given transaction has the same REQUEST_ID. | keyword |  |  |
| salesforce.login.request_status | The status of the request for a page view or user interface action. | keyword |  |  |
| salesforce.login.run_time | The amount of time that the request took in milliseconds. | float | ms | gauge |
| salesforce.login.uri_derived_id | The 18-character case insensitive ID of the URI of the page that's receiving the request. | keyword |  |  |
| salesforce.login.user_id | The 15-character ID of the user who's using Salesforce services through the UI or the API. | keyword |  |  |
| source.geo.city_name | City name. | keyword |  |  |
| source.geo.continent_name | Name of the continent. | keyword |  |  |
| source.geo.country_iso_code | Country ISO code. | keyword |  |  |
| source.geo.country_name | Country name. | keyword |  |  |
| source.geo.location | Longitude and latitude. | geo_point |  |  |
| source.geo.region_iso_code | Region ISO code. | keyword |  |  |
| source.geo.region_name | Region name. | keyword |  |  |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |  |  |
| tls.version | Numeric part of the version parsed from the original string. | keyword |  |  |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |  |  |
| user.email | User email address. | keyword |  |  |
| user.id | Unique identifier of the user. | keyword |  |  |
| user.roles | Array of user roles at the time of the event. | keyword |  |  |
| user_agent.name | Name of the user agent. | keyword |  |  |


### Login Stream

This is the `login_stream` data stream. It represents events containing details about the user's organization's login history.

An example event for `login_stream` looks as following:

```json
{
    "@timestamp": "2022-12-28T11:47:22.000Z",
    "agent": {
        "ephemeral_id": "ec47b43f-2817-4784-8632-afcaef0577c0",
        "id": "19ec90b1-6453-4383-97de-c2add7c43ab2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.0"
    },
    "data_stream": {
        "dataset": "salesforce.login_stream",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "19ec90b1-6453-4383-97de-c2add7c43ab2",
        "snapshot": false,
        "version": "8.7.0"
    },
    "event": {
        "action": "login-attempt",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2022-12-28T11:47:30.000Z",
        "dataset": "salesforce.login_stream",
        "id": "06af6d92-1167-467d-a826-ee8583f7134d",
        "ingested": "2023-01-16T07:18:42Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{ \"EventDate\": \"2022-12-28T11:47:22Z\", \"AuthServiceId\": \"06af6d92deqFAwqDaS\", \"CountryIso\": \"IN\", \"Platform\": \"Unknown\", \"EvaluationTime\": 0.0, \"CipherSuite\": \"ECDHE-RSA-AES256-GCM-SHA384\", \"PostalCode\": \"395007\", \"ClientVersion\": \"N/A\", \"LoginGeoId\": \"04F5j00000FadrI\", \"LoginUrl\": \"login.salesforce.com\", \"LoginHistoryId\": \"0Ya5j00000GLxCdCAL\", \"CreatedById\": \"0055j000000q9s7AAA\", \"SessionKey\": \"vMASKIU6AxEr+Op5\", \"ApiType\": \"N/A\", \"AuthMethodReference\": \"RFC 8176\", \"LoginType\": \"Remote Access 2.0\", \"PolicyOutcome\": \"Notified\", \"Status\": \"Success\", \"AdditionalInfo\": \"{}\", \"ApiVersion\": \"N/A\", \"EventIdentifier\": \"06af6d92-1167-467d-a826-ee8583f7134d\", \"RelatedEventIdentifier\": \"bd76f3e7-9ee5-4400-9e7f-54de57ecd79c\", \"LoginLatitude\": 21.1888, \"City\": \"Surat\", \"Subdivision\": \"Gujarat\", \"SourceIp\": \"81.2.69.142\", \"Username\": \"user@elastic.co\", \"UserId\": \"0055j000000utlPAAQ\", \"CreatedDate\": \"2022-12-28T11:47:30Z\", \"Country\": \"India\", \"LoginLongitude\": 72.8293, \"TlsProtocol\": \"TLS 1.2\", \"LoginKey\": \"o3vhFaSRBb0OzpCl\", \"Application\": \"elastic integration\", \"UserType\": \"Standard\", \"PolicyId\": \"0NIB000000000KOOAY\", \"HttpMethod\": \"POST\", \"SessionLevel\": \"STANDARD\", \"Browser\": \"Unknown\" }",
        "outcome": "success",
        "type": [
            "info"
        ],
        "url": "login.salesforce.com"
    },
    "http": {
        "request": {
            "body": {
                "content": "{}"
            },
            "method": "POST"
        }
    },
    "input": {
        "type": "cometd"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "salesforce": {
        "instance_url": "https://instance-url.salesforce.com",
        "login": {
            "access_mode": "Stream",
            "api": {
                "type": "N/A",
                "version": "N/A"
            },
            "application": "elastic integration",
            "auth": {
                "method_reference": "RFC 8176",
                "service_id": "06af6d92deqFAwqDaS"
            },
            "channel_name": "/event/LoginEventStream",
            "client_version": "N/A",
            "evaluation_time": 0,
            "geo_id": "04F5j00000FadrI",
            "history_id": "0Ya5j00000GLxCdCAL",
            "key": "o3vhFaSRBb0OzpCl",
            "policy_id": "0NIB000000000KOOAY",
            "policy_outcome": "Notified",
            "related_event_identifier": "bd76f3e7-9ee5-4400-9e7f-54de57ecd79c",
            "session": {
                "key": "vMASKIU6AxEr+Op5",
                "level": "STANDARD"
            },
            "type": "Remote Access 2.0"
        }
    },
    "source": {
        "geo": {
            "city_name": "Surat",
            "country_iso_code": "IN",
            "country_name": "India",
            "location": {
                "lat": 21.1888,
                "lon": 72.8293
            },
            "postal_code": "395007",
            "region_name": "Gujarat"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "salesforce-login_stream",
        "forwarded"
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
        "name": "Unknown",
        "os": {
            "platform": "Unknown"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |  |  |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |  |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |  |  |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |  |  |
| http.request.body.content | The full HTTP request body. | wildcard |  |  |
| http.request.body.content.text | Multi-field of `http.request.body.content`. | match_only_text |  |  |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |  |  |
| input.type | Input type. | keyword |  |  |
| related.ip | All of the IPs seen on your event. | ip |  |  |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |  |  |
| salesforce.login.access_mode | The mode of collecting logs from Salesforce - "REST" or "Stream". | keyword |  |  |
| salesforce.login.api.type | The type of API that's used to login. | keyword |  |  |
| salesforce.login.api.version | The version number of the API. If no version number is available, "Unknown" is returned. | keyword |  |  |
| salesforce.login.application | The application used to access the organization. | keyword |  |  |
| salesforce.login.auth.method_reference | The authentication method used by a third-party identification provider for an OpenID Connect single sign-on protocol. | keyword |  |  |
| salesforce.login.auth.service_id | The 18-character ID for an authentication service for a login event. | keyword |  |  |
| salesforce.login.channel_name | The Salesforce generic subscription Push Topic name. | keyword |  |  |
| salesforce.login.client_version | The version number of the login client. If no version number is available, "Unknown" is returned. | keyword |  |  |
| salesforce.login.evaluation_time | The amount of time it took to evaluate the transaction security policy, in milliseconds. | float | ms | gauge |
| salesforce.login.geo_id | The Salesforce ID of the geolocation information associated with the login user's IP address. | keyword |  |  |
| salesforce.login.history_id | Tracks a user session so you can correlate user activity with a particular login instance. | keyword |  |  |
| salesforce.login.key | The string that ties together all events in a given user's login session. The session starts with a login event and ends with either a logout event or the user session expiring. | keyword |  |  |
| salesforce.login.policy_id | The ID of the transaction security policy associated with this event. | keyword |  |  |
| salesforce.login.policy_outcome | The result of the transaction policy. | keyword |  |  |
| salesforce.login.related_event_identifier | Represents the EventIdentifier of the related event. | keyword |  |  |
| salesforce.login.session.key | The user's unique session ID. Use this value to identify all user events within a session. When a user logs out and logs in again, a new session is started. | keyword |  |  |
| salesforce.login.session.level | Session-level security controls user access to features that support it, such as connected apps and reporting. | keyword |  |  |
| salesforce.login.type | The type of login used to access the session. | keyword |  |  |
| source.geo.city_name | City name. | keyword |  |  |
| source.geo.continent_name | Name of the continent. | keyword |  |  |
| source.geo.country_iso_code | Country ISO code. | keyword |  |  |
| source.geo.country_name | Country name. | keyword |  |  |
| source.geo.location | Longitude and latitude. | geo_point |  |  |
| source.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |  |  |
| source.geo.region_iso_code | Region ISO code. | keyword |  |  |
| source.geo.region_name | Region name. | keyword |  |  |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |  |  |
| tls.version | Numeric part of the version parsed from the original string. | keyword |  |  |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |  |  |
| user.email | User email address. | keyword |  |  |
| user.id | Unique identifier of the user. | keyword |  |  |
| user.roles | Array of user roles at the time of the event. | keyword |  |  |
| user_agent.name | Name of the user agent. | keyword |  |  |
| user_agent.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |


### Logout Rest

This is the `logout_rest` data stream. It represents events containing details about the user's organization's logout history.

An example event for `logout_rest` looks as following:

```json
{
    "@timestamp": "2022-11-22T07:37:25.779Z",
    "agent": {
        "ephemeral_id": "49171880-184e-4712-bef1-97619368d729",
        "id": "e8ad8355-f296-4e32-9096-2df7c9cc7e97",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "data_stream": {
        "dataset": "salesforce.logout_rest",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "e8ad8355-f296-4e32-9096-2df7c9cc7e97",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "action": "logout",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "code": "4exLFFQZ1234xFl1cJNwOV",
        "created": "2022-12-15T10:29:49.953Z",
        "dataset": "salesforce.logout_rest",
        "ingested": "2022-12-15T10:29:53Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"API_TYPE\":\"f\",\"API_VERSION\":\"54.0\",\"APP_TYPE\":\"1000\",\"BROWSER_TYPE\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36\",\"CLIENT_IP\":\"81.2.69.142\",\"CLIENT_VERSION\":\"9998\",\"EVENT_TYPE\":\"Logout\",\"LOGIN_KEY\":\"Obv9123BzbaxqCo1\",\"ORGANIZATION_ID\":\"00D5j001234VI3n\",\"PLATFORM_TYPE\":\"1015\",\"REQUEST_ID\":\"4exLFFQZ1234xFl1cJNwOV\",\"RESOLUTION_TYPE\":\"9999\",\"SESSION_KEY\":\"WvtsJ1235oW24EbH\",\"SESSION_LEVEL\":\"1\",\"SESSION_TYPE\":\"O\",\"TIMESTAMP\":\"20221122073725.779\",\"TIMESTAMP_DERIVED\":\"2022-11-22T07:37:25.779Z\",\"USER_ID\":\"0055j000000utlP\",\"USER_ID_DERIVED\":\"0055j000000utlPAAQ\",\"USER_INITIATED_LOGOUT\":\"0\",\"USER_TYPE\":\"S\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "salesforce": {
        "instance_url": "http://elastic-package-service_salesforce_1:8010",
        "logout": {
            "access_mode": "REST",
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
        "salesforce-logout_rest",
        "forwarded"
    ],
    "user": {
        "id": "0055j000000utlPAAQ",
        "roles": [
            "Standard"
        ]
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Input type. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |
| salesforce.logout.access_mode | Mode of Salesforce API from which the event is collected. | keyword |
| salesforce.logout.api.type | The type of Salesforce API request. | keyword |
| salesforce.logout.api.version | The version of the Salesforce API that's being used. | keyword |
| salesforce.logout.app_type | The application type that was in use upon logging out. | keyword |
| salesforce.logout.browser_type | The identifier string returned by the browser used at login. | keyword |
| salesforce.logout.client_version | The version of the client that was in use upon logging out. | keyword |
| salesforce.logout.event_type | The type of event. The value is always Logout. | keyword |
| salesforce.logout.login_key | The string that ties together all events in a given user's logout session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |
| salesforce.logout.organization_id | The 15-character ID of the organization. | keyword |
| salesforce.logout.platform_type | The code for the client platform. If a timeout caused the logout, this field is null. | keyword |
| salesforce.logout.resolution_type | TThe screen resolution of the client. If a timeout caused the logout, this field is null. | keyword |
| salesforce.logout.session.level | The security level of the session that was used when logging out (e.g. Standard Session or High-Assurance Session). | keyword |
| salesforce.logout.session.type | The session type that was used when logging out (e.g. API, Oauth2 or UI). | keyword |
| salesforce.logout.user_id | The 15-character ID of the user who's using Salesforce services through the UI or the API. | keyword |
| salesforce.logout.user_initiated_logout | The value is 1 if the user intentionally logged out of the organization by clicking the Logout button. If the user's session timed out due to inactivity or another implicit logout action, the value is 0. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.roles | Array of user roles at the time of the event. | keyword |


### Logout Stream

This is the `logout_stream` data stream. It represents events containing details about the user's organization's logout history.

An example event for `logout_stream` looks as following:

```json
{
    "@timestamp": "2022-12-29T11:38:54.000Z",
    "agent": {
        "ephemeral_id": "ec47b43f-2817-4784-8632-afcaef0577c0",
        "id": "19ec90b1-6453-4383-97de-c2add7c43ab2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.0"
    },
    "data_stream": {
        "dataset": "salesforce.logout_stream",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "19ec90b1-6453-4383-97de-c2add7c43ab2",
        "snapshot": false,
        "version": "8.7.0"
    },
    "event": {
        "action": "logout-attempt",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2022-12-29T11:38:54.000Z",
        "dataset": "salesforce.logout_stream",
        "id": "06ce4a9d-8d6b-4a71-aad8-04d28c9a43df",
        "ingested": "2023-01-16T07:18:42Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{ \"EventDate\": \"2022-12-29T11:38:54Z\", \"EventIdentifier\": \"06ce4a9d-8d6b-4a71-aad8-04d28c9a43df\", \"SourceIp\": \"81.2.69.142\", \"CreatedById\": \"0055j000000q9s7AAA\", \"Username\": \"user@elastic.co\", \"UserId\": \"0055j000000utlPAAQ\", \"RelatedEventIdentifier\": null, \"SessionKey\": \"6/HAElgoPCwskqBU\", \"CreatedDate\": \"2022-12-29T11:38:54Z\", \"LoginKey\": \"CuRVtbMjat6xxbTH\", \"SessionLevel\": \"STANDARD\" }",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cometd"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "salesforce": {
        "instance_url": "https://instance-url.salesforce.com",
        "logout": {
            "access_mode": "Stream",
            "channel_name": "/event/LogoutEventStream",
            "login_key": "CuRVtbMjat6xxbTH",
            "session": {
                "key": "6/HAElgoPCwskqBU",
                "level": "STANDARD"
            }
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
        "salesforce-logout_stream",
        "forwarded"
    ],
    "user": {
        "email": "user@elastic.co",
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Input type. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |
| salesforce.logout.access_mode | The mode of collecting logs from Salesforce - "REST" or "Stream". | keyword |
| salesforce.logout.channel_name | The Salesforce generic subscription Push Topic name. | keyword |
| salesforce.logout.login_key | The string that ties together all events in a given user's logout session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |
| salesforce.logout.related_event_identifier | Represents the event.id of the related event. | keyword |
| salesforce.logout.session.key | The user's unique session ID. You can use this value to identify all user events within a session. When a user logs out and logs in again, a new session is started. | keyword |
| salesforce.logout.session.level | Indicates the session-level security of the session that the user is logging out of for this event. Session-level security controls user access to features that support it, such as connected apps and reporting. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |


### SetupAuditTrail

This is the `setupaudittrail` data stream. It represents changes users made in the user's organization's Setup area for at least the last 180 days.

An example event for `setupaudittrail` looks as following:

```json
{
    "@timestamp": "2022-08-16T09:26:38.000Z",
    "agent": {
        "ephemeral_id": "cf463665-f17d-4155-8434-4f93e0fabd18",
        "id": "511d10d2-be41-45d0-9712-40b7ce035864",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "data_stream": {
        "dataset": "salesforce.setupaudittrail",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "511d10d2-be41-45d0-9712-40b7ce035864",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "action": "insertConnectedApplication",
        "agent_id_status": "verified",
        "created": "2022-08-16T09:26:38.000Z",
        "dataset": "salesforce.setupaudittrail",
        "id": "0Ym5j000019nwonCAA",
        "ingested": "2023-01-04T15:34:45Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"Action\":\"insertConnectedApplication\",\"CreatedByContext\":\"Einstein\",\"CreatedById\":\"0055j000000utlPAAQ\",\"CreatedByIssuer\":null,\"CreatedDate\":\"2022-08-16T09:26:38.000+0000\",\"DelegateUser\":\"user1\",\"Display\":\"For user user@elastic.co, the User Verified Email status changed to verified\",\"Id\":\"0Ym5j000019nwonCAA\",\"Section\":\"Connected Apps\",\"attributes\":{\"type\":\"SetupAuditTrail\",\"url\":\"/services/data/v54.0/sobjects/SetupAuditTrail/0Ym5j000019nwonCAA\"}}",
        "type": [
            "admin"
        ],
        "url": "/services/data/v54.0/sobjects/SetupAuditTrail/0Ym5j000019nwonCAA"
    },
    "input": {
        "type": "httpjson"
    },
    "salesforce": {
        "instance_url": "http://elastic-package-service_salesforce_1:8010",
        "setup_audit_trail": {
            "access_mode": "REST",
            "created_by_context": "Einstein",
            "created_by_id": "0055j000000utlPAAQ",
            "delegate_user": "user1",
            "display": "For user user@elastic.co, the User Verified Email status changed to verified",
            "event_type": "SetupAuditTrail",
            "section": "Connected Apps"
        }
    },
    "tags": [
        "preserve_original_event",
        "salesforce-setupaudittrail",
        "forwarded"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| input.type | Input type. | keyword |
| salesforce.instance_url | The Instance URL of the Salesforce instance. | keyword |
| salesforce.setup_audit_trail.access_mode | Type of API from which the event is collected. | keyword |
| salesforce.setup_audit_trail.created_by_context | The context under which the Setup change was made. For example, if Einstein uses cloud-to-cloud services to make a change in Setup, the value of this field is Einstein. | keyword |
| salesforce.setup_audit_trail.created_by_id | The id under which the Setup change was made. For example, if Einstein uses cloud-to-cloud services to make a change in Setup, the value of this field is id of Einstein. | keyword |
| salesforce.setup_audit_trail.created_by_issuer | Reserved for future use. | keyword |
| salesforce.setup_audit_trail.delegate_user | The Login-As user who executed the action in Setup. If a Login-As user didn't perform the action, this field is empty string. This field is available in API version 35.0 and later. | keyword |
| salesforce.setup_audit_trail.display | The full description of changes made in Setup. For example, if the event.action field has a value of PermSetCreate, the Display field has a value like "Created permission set MAD: with user license Salesforce." | keyword |
| salesforce.setup_audit_trail.event_type | Event type. | keyword |
| salesforce.setup_audit_trail.section | The section in the Setup menu where the action occurred. For example, Manage Users or Company Profile. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

