# Salesforce Integration

## Overview

The Salesforce integration allows you to monitor a [Salesforce](https://www.salesforce.com/) instance. Salesforce is a customer relationship management (CRM) platform. It provides an ecosystem for businesses to manage marketing, sales, commerce, service, and IT teams from anywhere with one integrated CRM platform.

Use the Salesforce integration to:
- Gain insights into login and other operational activities by the users of your organization.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

As an example, you can use the data from this integration to understand the activity patterns of users based on region or the distribution of users by license type. 

## Data streams

The Salesforce integration collects log events using the REST API of Salesforce.

**Logs** help you keep a record of events happening in Salesforce.
Log data streams collected by the Salesforce integration include [Login](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_login.htm), and [Logout](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_logout.htm).

Data streams:
- `login_rest`: Tracks login activity of users who log in to Salesforce.
- `logout_rest`: Tracks logout activity of users who logout from Salesforce.

## Compatibility

This integration has been tested against Salesforce `Spring '22 (v54.0) release`.

In order to find out the Salesforce version of your Instance, see below:

1. On the Home tab in Salesforce Classic, in the top right corner of the screen is a link to releases like `Summer '22`. This indicates your release.

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
The last one on the list is the release of your instance. In the example above, the version is `Summer '22` i.e. `v55.0`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

In your Salesforce instance, ensure that `API Enabled permission` is selected for the user profile. Follow the below steps to enable the same:

1. Go to `Setup` > `Quick Find` > `Users`, and Click on `Users`.
2. Click on the profile link associated with the `User Account` used for data collection.
3. Search for `API Enabled` permission on the same page. In case it’s not present, search it under `System Permissions` and check if `API Enabled` privilege is selected. If not, enable it for data collection.

## Set Up

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Configuration

You need the following information from your Salesforce instance to configure this integration in Elastic:

### Salesforce Instance URL

The instance your Salesforce Organization uses is indicated in the URL of your browser's address bar in Salesforce Classic. The value before 'salesforce.com' is your Salesforce Instance.

Example URL: `https://na9.salesforce.com/home/home.jsp`

In the above example, the value before 'salesforce.com' is your Salesforce Instance. In this example, the Salesforce Organization is located on NA9. 

The Salesforce Instance URL is: `https://na9.salesforce.com`

In Salesforce Lightning, it is available under the user name in the “View Profile” tab.

### Client Key and Client Secret for Authentication

In order to use this integration, you need to create a new Salesforce Application using OAuth. Follow the steps below to create a connected application in Salesforce:

1. Login to [Salesforce](https://login.salesforce.com/) with the same user credentials that you want to collect data with.
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

Follow the steps below, in case you need to find the API version:

1. Go to `Setup` > `Quick Find` > `Apex Classes`.
2. Click the `New` button.
3. Click the `Version Settings` tab.
4. Refer to the `Version` dropdown for the API Version number.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Salesforce Integration should display a list of available dashboards. Click on the dashboard available for your configured datastream. It should be populated with the required data.

## Troubleshooting

- In case of data ingestion if the user finds the following type of error logs:
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
2. Click on the Connected App name created by you to generate the client id and client secret (Refer to Client Key and Client Secret for Authentication) under the Master Label.
3. Click on Edit Policies, and select `Relax IP restrictions` from the dropdown for IP Relaxation.

## Logs reference

### Login Rest

This is the `login_rest` data stream. It represents events containing details about your organization's user login history.

An example event for `login_rest` looks as following:

```json
{
    "@timestamp": "2022-11-22T04:46:15.591Z",
    "agent": {
        "ephemeral_id": "7091b66c-e647-42f9-9c3e-d0753552a291",
        "id": "e8ad8355-f296-4e32-9096-2df7c9cc7e97",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
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
        "id": "e8ad8355-f296-4e32-9096-2df7c9cc7e97",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "action": "login-attempt",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2022-12-15T10:29:06.958Z",
        "dataset": "salesforce.login_rest",
        "ingested": "2022-12-15T10:29:10Z",
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
        "roles": "Standard"
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


### Logout Rest

This is the `logout_rest` data stream. It represents events containing details about your organization's user logout history.

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
        "roles": "Standard"
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

