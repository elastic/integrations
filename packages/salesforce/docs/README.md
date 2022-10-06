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

### Apex

This is the `apex` data stream. Apex enables developers to access the Salesforce platform back-end database and client-server interfaces to create third-party SaaS applications.

An example event for `apex` looks as following:

```json
{
    "@timestamp": "2021-11-02T09:12:50.488Z",
    "agent": {
        "ephemeral_id": "f1a11f0f-f853-42e7-b8ff-72201f8ea229",
        "id": "dbe82fcc-9eea-4080-91fe-9f4a6afa87ee",
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
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "dbe82fcc-9eea-4080-91fe-9f4a6afa87ee",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "action": "apex-callout",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2022-10-04T11:41:10.795Z",
        "dataset": "salesforce.apex",
        "duration": 1293,
        "ingested": "2022-10-04T11:41:14Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"CLIENT_IP\":\"127.0.0.1\",\"CPU_TIME\":\"10\",\"EVENT_TYPE\":\"ApexCallout\",\"LOGIN_KEY\":\"ABCDEFGH\",\"METHOD\":\"GET\",\"ORGANIZATION_ID\":\"00D5j000000VABC\",\"REQUEST_ID\":\"ABCDE\",\"REQUEST_SIZE\":\"10\",\"RESPONSE_SIZE\":\"256\",\"RUN_TIME\":\"1305\",\"SESSION_KEY\":\"ABCDEF\",\"SUCCESS\":\"1\",\"TIME\":\"1293\",\"TIMESTAMP\":\"20211102091250.488\",\"TIMESTAMP_DERIVED\":\"2021-11-02T09:12:50.488Z\",\"TYPE\":\"OData\",\"URI\":\"CALLOUT-LOG\",\"URI_ID_DERIVED\":\"0055j000000utlPABCD\",\"URL\":\"https://temp.sh/odata/Accounts\",\"USER_ID\":\"0055j000000ABCD\",\"USER_ID_DERIVED\":\"0055j012345utlPAAQ\"}",
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
            "127.0.0.1"
        ]
    },
    "salesforce": {
        "apex": {
            "access_mode": "rest",
            "cpu_time": 10,
            "event_type": "ApexCallout",
            "login_key": "ABCDEFGH",
            "organization_id": "00D5j000000VABC",
            "request_id": "ABCDE",
            "run_time": 1305,
            "type": "OData",
            "uri": "CALLOUT-LOG",
            "uri_derived_id": "0055j000000utlPABCD",
            "user_id_derived": "0055j012345utlPAAQ"
        }
    },
    "source": {
        "ip": "127.0.0.1"
    },
    "tags": [
        "preserve_original_event",
        "salesforce-apex",
        "forwarded"
    ],
    "user": {
        "id": "0055j000000ABCD"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |
| event.id | Unique ID to describe the event. | keyword |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |  |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |  |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |  |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |  |
| http.response.status_code | HTTP response status code. | long |  |
| input.type | Input type. | keyword |  |
| related.ip | All of the IPs seen on your event. | ip |  |
| salesforce.apex.access_mode | The mode of collecting logs from Salesforce - "rest" or "stream". | keyword |  |
| salesforce.apex.action | Action performed by the callout. | keyword |  |
| salesforce.apex.callout_time | Time spent waiting on webservice callouts, in milliseconds. | long | ms |
| salesforce.apex.class_name | The Apex class name. If the class is part of a managed package, this string includes the package namespace. | keyword |  |
| salesforce.apex.client_name | The name of the client that's using Salesforce services. This field is an optional parameter that can be passed in API calls. If blank, the caller didnt specify a client in the CallOptions header. | keyword |  |
| salesforce.apex.cpu_time | The CPU time in milliseconds used to complete the request. | long | ms |
| salesforce.apex.db_blocks | Indicates how much activity is occurring in the database. A high value for this field suggests that adding indexes or filters on your queries would benefit performance. | keyword |  |
| salesforce.apex.db_cpu_time | The CPU time in milliseconds to complete the request. Indicates the amount of activity taking place in the database layer during the request. | long | ms |
| salesforce.apex.db_time.total | Time (in milliseconds) spent waiting for database processing in aggregate for all operations in the request. Compare this field to CPU_TIME to determine whether performance issues are occurring in the database layer or in your own code. | long | ms |
| salesforce.apex.entity | Name of the external object being accessed. | keyword |  |
| salesforce.apex.entity_name | The name of the object affected by the trigger. | keyword |  |
| salesforce.apex.entry_point | The entry point for this Apex execution. | keyword |  |
| salesforce.apex.event_type | The type of event. | keyword |  |
| salesforce.apex.execute.ms | How long it took (in milliseconds) for Salesforce to prepare and execute the query. Available in API version 42.0 and later. | long | ms |
| salesforce.apex.fetch.ms | How long it took (in milliseconds) to retrieve the query results from the external system. Available in API version 42.0 and later. | long | ms |
| salesforce.apex.fields.count | The number of fields or columns, where applicable. | keyword |  |
| salesforce.apex.filter | Field expressions to filter which rows to return. Corresponds to WHERE in SOQL queries. | keyword |  |
| salesforce.apex.is_long_running_request | Indicates whether the request is counted against your org's concurrent long-running Apex request limit (true) or not (false). | keyword |  |
| salesforce.apex.limit | Maximum number of rows to return for a query. Corresponds to LIMIT in SOQL queries. | keyword |  |
| salesforce.apex.limit_usage.pct | The percentage of Apex SOAP calls that were made against the organization's limit. | keyword |  |
| salesforce.apex.login_key | The string that ties together all events in a given user's login session. It starts with a login event and ends with either a logout event or the user session expiring. | keyword |  |
| salesforce.apex.media_type | The media type of the response. | keyword |  |
| salesforce.apex.message | Error or warning message associated with the failed call. | keyword |  |
| salesforce.apex.method_name | The name of the calling Apex method. | keyword |  |
| salesforce.apex.offset | Number of rows to skip when paging through a result set. Corresponds to OFFSET in SOQL queries. | keyword |  |
| salesforce.apex.orderby | Field or column to use for sorting query results, and whether to sort the results in ascending (default) or descending order. Corresponds to ORDER BY in SOQL queries. | keyword |  |
| salesforce.apex.organization_id | The 15-character ID of the organization. | keyword |  |
| salesforce.apex.query | The SOQL query, if one was performed. | keyword |  |
| salesforce.apex.quiddity | The type of outer execution associated with this event. | keyword |  |
| salesforce.apex.request_id | The unique ID of a single transaction. A transaction can contain one or more events. Each event in a given transaction has the same REQUEST_ID. | keyword |  |
| salesforce.apex.request_status | The status of the request for a page view or user interface action. | keyword |  |
| salesforce.apex.rows.fetched | Number of rows fetched by the callout. Available in API version 42.0 and later. | keyword |  |
| salesforce.apex.rows.processed | The number of rows that were processed in the request. | keyword |  |
| salesforce.apex.rows.total | Total number of records in the result set. The value is always -1 if the custom adapter's DataSource.Provider class doesn't declare the QUERY_TOTAL_SIZE capability. | keyword |  |
| salesforce.apex.run_time | Not used for this event type. Use the TIME field instead. | long | ms |
| salesforce.apex.select | Comma-separated list of fields being queried. Corresponds to SELECT in SOQL queries. | keyword |  |
| salesforce.apex.soql_queries.count | The number of SOQL queries that were executed during the event. | keyword |  |
| salesforce.apex.subqueries | Reserved for future use. | keyword |  |
| salesforce.apex.throughput | Number of records retrieved in one second. | keyword |  |
| salesforce.apex.trigger.id | The 15-character ID of the trigger that was fired. | keyword |  |
| salesforce.apex.trigger.name | For triggers coming from managed packages, TRIGGER_NAME includes a namespace prefix separated with a . character. If no namespace prefix is present, the trigger is from an unmanaged trigger. | keyword |  |
| salesforce.apex.trigger.type | The type of this trigger. | keyword |  |
| salesforce.apex.type | The type of Apex callout. | keyword |  |
| salesforce.apex.uri | The URI of the page that's receiving the request. | keyword |  |
| salesforce.apex.uri_derived_id | The 18-character case-safe ID of the URI of the page that's receiving the request. | keyword |  |
| salesforce.apex.user_agent | The numeric code for the type of client used to make the request (for example, the browser, application, or API). | keyword |  |
| salesforce.apex.user_id_derived | The 18-character case-safe ID of the user who's using Salesforce services through the UI or the API. | keyword |  |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |  |
| tags | List of keywords used to tag each event. | keyword |  |
| user.id | Unique identifier of the user. | keyword |  |
| user.name | Short name or login of the user. | keyword |  |
| user.name.text | Multi-field of `user.name`. | match_only_text |  |
| user.roles | Array of user roles at the time of the event. | keyword |  |

