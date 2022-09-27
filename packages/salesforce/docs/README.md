# Salesforce Integration

## Overview

The Salesforce integration allows you to monitor [Salesforce](https://www.salesforce.com/) instance. Salesforce provides customer relationship management service and also provides enterprise applications focused on customer service, marketing automation, analytics, and application development.

Use the Salesforce integration to get visibility into the Salesforce Org operations and hold Salesforce accountable to the Service Level Agreements. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, if you want to check the number of successful and failed login attempts over time, you could check the same based on the ingested events or the visualization. Then you can create visualizations, alerts and troubleshoot by looking at the documents ingested in Elasticsearch.

## Data streams

The Salesforce integration collects log events using REST and Streaming API of Salesforce.

**Logs** help you keep a record of events happening in Salesforce.
Log data streams collected by the Salesforce integration include [Login](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_login.htm) (using REST and Streaming API), [Logout](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_logout.htm) (using REST and Streaming API), [Apex](https://developer.salesforce.com/docs/atlas.en-us.238.0.object_reference.meta/object_reference/sforce_api_objects_apexclass.htm), and [SetupAuditTrail](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_setupaudittrail.htm).

This integration uses:
- `httpjson` filebeat input to collect `login_rest`, `logout_rest`, `apex` and `setupaudittrail` events.
- `cometd` filebeat input to collect `login_stream` and `logout_stream` events.

## Compatibility

This integration has been tested against Salesforce API version `v54.0`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Logs reference

### Logout Rest

This is the `logout_rest` data stream. It represents events containing details about your organization's user logout history.

An example event for `logout_rest` looks as following:

```json
{
    "@timestamp": "2022-09-19T07:37:07.360Z",
    "agent": {
        "ephemeral_id": "9214e0a5-bd4e-4cf9-94c9-f6c91645a0cd",
        "id": "d81be70a-a7c5-4378-a35a-65460992be69",
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
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "d81be70a-a7c5-4378-a35a-65460992be69",
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
        "created": "2022-09-27T13:09:53.176Z",
        "dataset": "salesforce.logout_rest",
        "ingested": "2022-09-27T13:09:56Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"API_TYPE\":\"f\",\"API_VERSION\":\"54.0\",\"APP_TYPE\":\"1000\",\"BROWSER_TYPE\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36\",\"CLIENT_IP\":\"43.200.10.11\",\"CLIENT_VERSION\":\"9998\",\"EVENT_TYPE\":\"Logout\",\"LOGIN_KEY\":\"Obv9123BzbaxqCo1\",\"ORGANIZATION_ID\":\"00D5j001234VI3n\",\"PLATFORM_TYPE\":\"1015\",\"REQUEST_ID\":\"4exLFFQZ1234xFl1cJNwOV\",\"RESOLUTION_TYPE\":\"9999\",\"SESSION_KEY\":\"WvtsJ1235oW24EbH\",\"SESSION_LEVEL\":\"1\",\"SESSION_TYPE\":\"O\",\"TIMESTAMP\":\"20220919073707.360\",\"TIMESTAMP_DERIVED\":\"2022-09-19T07:37:07.360Z\",\"USER_ID\":\"0055j000000utlP\",\"USER_ID_DERIVED\":\"0055j000000utlPAAQ\",\"USER_INITIATED_LOGOUT\":\"0\",\"USER_TYPE\":\"S\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "43.200.10.11"
        ]
    },
    "salesforce": {
        "logout": {
            "access_mode": "rest",
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
        "ip": "43.200.10.11"
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
| salesforce.logout.access_mode | Mode of API from which the event is collected. | keyword |
| salesforce.logout.api.type | The type of API request. | keyword |
| salesforce.logout.api.version | The version of the API that's being used. | keyword |
| salesforce.logout.app_type | The application type that was in use upon logging out. | keyword |
| salesforce.logout.browser_type | The identifier string returned by the browser used at login. | keyword |
| salesforce.logout.client_version | The version of the client that was in use upon logging out. | keyword |
| salesforce.logout.event_type | The type of event. The value is always Logout. | keyword |
| salesforce.logout.login_key | The string that ties together all events in a given user's login session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |
| salesforce.logout.organization_id | The 15-character ID of the organization. | keyword |
| salesforce.logout.platform_type | The code for the client platform. If a timeout caused the logout, this field is null. | keyword |
| salesforce.logout.resolution_type | TThe screen resolution of the client. If a timeout caused the logout, this field is null. | keyword |
| salesforce.logout.session.level | The security level of the session that was used when logging out. | keyword |
| salesforce.logout.session.type | The session type that was used when logging out. | keyword |
| salesforce.logout.user_id | The 15-character ID of the user who's using Salesforce services through the UI or the API. | keyword |
| salesforce.logout.user_initiated_logout | The value is 1 if the user intentionally logged out of the organization by clicking the Logout button. If the user's session timed out due to inactivity or another implicit logout action, the value is 0. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location.lat | Longitude and latitude. | geo_point |
| source.geo.location.lon | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.roles | Array of user roles at the time of the event. | keyword |
