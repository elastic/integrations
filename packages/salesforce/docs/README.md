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

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Logs reference

### Login Rest

This is the `login_rest` data stream. It represents events containing details about your organization's user login history.

An example event for `login_rest` looks as following:

```json
{
    "@timestamp": "2021-10-06T07:13:07.550Z",
    "agent": {
        "ephemeral_id": "ee2331e8-fdcf-453c-803c-4f08328bdd78",
        "id": "2764cc15-ad17-412f-b4a6-fdc1357be72f",
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
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "2764cc15-ad17-412f-b4a6-fdc1357be72f",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "action": "login-attempt",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2022-09-21T13:21:19.180Z",
        "dataset": "salesforce.login_rest",
        "ingested": "2022-09-21T13:21:22Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\\\"API_TYPE\\\":\\\"f\\\",\\\"API_VERSION\\\":\\\"9998.0\\\",\\\"AUTHENTICATION_METHOD_REFERENCE\\\":\\\"\\\",\\\"BROWSER_TYPE\\\":\\\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36\\\",\\\"CIPHER_SUITE\\\":\\\"ECDHE-RSA-AES256-GCM-SHA384\\\",\\\"CLIENT_IP\\\":\\\"43.200.10.11\\\",\\\"CPU_TIME\\\":\\\"30\\\",\\\"DB_TOTAL_TIME\\\":\\\"52435102\\\",\\\"EVENT_TYPE\\\":\\\"Login\\\",\\\"LOGIN_KEY\\\":\\\"QfNecrLXSII6fsBq\\\",\\\"LOGIN_STATUS\\\":\\\"LOGIN_NO_ERROR\\\",\\\"ORGANIZATION_ID\\\":\\\"00D5j000000VI3n\\\",\\\"REQUEST_ID\\\":\\\"4ehU_U-nbQyAPFl1cJILm-\\\",\\\"REQUEST_STATUS\\\":\\\"Success\\\",\\\"RUN_TIME\\\":\\\"83\\\",\\\"SESSION_KEY\\\":\\\"\\\",\\\"SOURCE_IP\\\":\\\"43.200.10.11\\\",\\\"TIMESTAMP\\\":\\\"20211006071307.550\\\",\\\"TIMESTAMP_DERIVED\\\":\\\"2021-10-06T07:13:07.550Z\\\",\\\"TLS_PROTOCOL\\\":\\\"TLSv1.2\\\",\\\"URI\\\":\\\"/index.jsp\\\",\\\"URI_ID_DERIVED\\\":\\\"s4heK3WbH-lcJIL3-n\\\",\\\"USER_ID\\\":\\\"0055j000000utlP\\\",\\\"USER_ID_DERIVED\\\":\\\"0055j000000utlPAAQ\\\",\\\"USER_NAME\\\":\\\"user@elastic.co\\\",\\\"USER_TYPE\\\":\\\"Standard\\\"}",
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
            "43.200.10.11"
        ]
    },
    "salesforce": {
        "login": {
            "access_mode": "rest",
            "api": {
                "type": "Feed",
                "version": "9998.0"
            },
            "client_ip": "43.200.10.11",
            "cpu_time": "30",
            "db_time": {
                "total": "52435102"
            },
            "event_type": "Login",
            "key": "QfNecrLXSII6fsBq",
            "organization_id": "00D5j000000VI3n",
            "request_id": "4ehU_U-nbQyAPFl1cJILm-",
            "request_status": "Success",
            "run_time": "83",
            "uri_derived_id": "s4heK3WbH-lcJIL3-n",
            "user_id": "0055j000000utlP"
        }
    },
    "source": {
        "ip": "43.200.10.11"
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
| salesforce.login.access_mode | Mode of API from which the event is collected. | keyword |  |  |
| salesforce.login.api.type | The type of API request. | keyword |  |  |
| salesforce.login.api.version | The version of the API that's being used. | keyword |  |  |
| salesforce.login.auth.service_id | The authentication method used by a third-party identification provider for an OpenID Connect single sign-on protocol. | keyword |  |  |
| salesforce.login.client_ip | The IP address of the client that's using Salesforce services. A Salesforce internal IP (such as a login from Salesforce Workbench or AppExchange) is shown as “Salesforce.com IP”. | keyword |  |  |
| salesforce.login.cpu_time | The CPU time in milliseconds used to complete the request. This field indicates the amount of activity taking place in the app server layer. | keyword | ms | gauge |
| salesforce.login.db_time.total | The time in nanoseconds for a database round trip. Includes time spent in the JDBC driver, network to the database, and DB_CPU_TIME. Compare this field to CPU_TIME to determine whether performance issues are occurring in the database layer or in your own code. | keyword | nanos | gauge |
| salesforce.login.event_type | The type of event. The value is always Login. | keyword |  |  |
| salesforce.login.key | The string that ties together all events in a given user's login session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |  |  |
| salesforce.login.organization_id | The 15-character ID of the organization. | keyword |  |  |
| salesforce.login.request_id | The unique ID of a single transaction. A transaction can contain one or more events. Each event in a given transaction has the same REQUEST_ID. | keyword |  |  |
| salesforce.login.request_status | The status of the request for a page view or user interface action. | keyword |  |  |
| salesforce.login.run_time | The amount of time that the request took in milliseconds. | keyword | ms | gauge |
| salesforce.login.uri_derived_id | The 18-character case insensitive ID of the URI of the page that's receiving the request. | keyword |  |  |
| salesforce.login.user_id | The 15-character ID of the user who's using Salesforce services through the UI or the API. | keyword |  |  |
| source.geo.city_name | City name. | keyword |  |  |
| source.geo.continent_name | Name of the continent. | keyword |  |  |
| source.geo.country_iso_code | Country ISO code. | keyword |  |  |
| source.geo.country_name | Country name. | keyword |  |  |
| source.geo.location.lat | Longitude and latitude. | geo_point |  |  |
| source.geo.location.lon | Longitude and latitude. | geo_point |  |  |
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

