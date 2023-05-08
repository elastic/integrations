# Apache Tomcat Integration

## Overview

[Apache Tomcat](https://tomcat.apache.org/tomcat-10.1-doc/logging.html) is a free and open-source implementation of the jakarta servlet, jakarta expression language, and websocket technologies. It provides a pure java http web server environment in which java code can also run. Thus, it is a java web application server, although not a full JEE application server.

Use the Apache Tomcat integration to:

- Collect logs related to access and catalina.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Apache Tomcat integration collects logs data.

Logs help you keep a record of events that happen on your machine. The `Log` data streams collected by Apache Tomcat integration are `access` and `catalina`, so that users can keep track of the IP addresses of the clients, bytes returned to the client or sent by clients, etc., so that users could monitor and troubleshoot the performance of Java applications.

Data stream:
- `access`: Collects information related to overall performance of Java applications.
- `catalina`: Collects information related to the startup and shutdown of the Apache Tomcat application server, the deployment of new applications, or the failure of one or more subsystems.

Note:
- Users can monitor and see the log inside the ingested documents for Apache Tomcat in the `logs-*` index pattern from `Discover`.

## Compatibility

This integration has been tested against Apache Tomcat versions `10.1.5`, `9.0.71` and `8.5.85`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

## Steps to configure Filestream input for Access logs

Here are the steps to configure Log format in Apache Tomcat instance:

1. Go to `<tomcat_home>/conf/server.xml` from Apache Tomcat instance.

2. The user can update the log format in the pattern field of the class `org.apache.catalina.valves.AccessLogValve`. Here is an example of the `org.apache.catalina.valves.AccessLogValve` class.

```
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
       prefix="localhost_access_log" suffix=".txt"
       pattern='%h %l %u %t "%r" %s %b %A %X %T "%{Referer}i" "%{User-Agent}i" X-Forwarded-For="%{X-Forwarded-For}i"' />
```

3. The supported log formats are:
```
Common Log Format :- '%h %l %u %t "%r" %s %b'
Combined Log Format :- '%h %l %u %t "%r" %s %b "%{Referrer}i" "%{User-Agent}i"'
Combined Log Format + X-Forwarded-For header :- '%h %l %u %t "%r" %s %b %A %X %T "%{Referer}i" "%{User-Agent}i" X-Forwarded-For="%{X-Forwarded-For}i"'
```

4. Run the following commands to restart Apache Tomcat instance: -

```
systemctl restart tomcat
```

Note:
- Restarting Apache Tomcat does not affect the virtual desktops that are currently running. It will only prevent new users from logging in for the duration of the restart process (typically several seconds).

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Apache Tomcat Integration should display a list of available dashboards. Click on the dashboard available for your configured data stream. It should be populated with the required data.

## Logs reference

### Access

This is the `Access` data stream. This data stream collects logs related to overall performance of Java applications.

An example event for `access` looks as following:

```json
{
    "@timestamp": "2023-05-02T10:23:04.000Z",
    "agent": {
        "ephemeral_id": "919ea0c0-7f5c-4fc9-b7cf-288a0f913454",
        "id": "41c81fe5-7323-4e84-b501-ddad2fa3530a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.0"
    },
    "apache_tomcat": {
        "access": {
            "http": {
                "ident": "-",
                "useragent": "-"
            }
        }
    },
    "data_stream": {
        "dataset": "apache_tomcat.access",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 11235
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "41c81fe5-7323-4e84-b501-ddad2fa3530a",
        "snapshot": false,
        "version": "8.7.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "apache_tomcat.access",
        "ingested": "2023-05-02T10:23:27Z",
        "kind": "event",
        "module": "apache_tomcat",
        "original": "127.0.0.1 - - [02/May/2023:10:23:04 +0000] \"GET / HTTP/1.1\" 200 11235",
        "outcome": "success",
        "type": [
            "access"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/localhost_access_log.2023-05-02.txt"
        },
        "offset": 0
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "source": {
        "ip": "127.0.0.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "apache_tomcat-access"
    ],
    "url": {
        "original": "/",
        "path": "/"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| apache_tomcat.access.connection_status | Connection status when response is completed. | keyword |  |
| apache_tomcat.access.header_forwarder | Header forwarder of log. | ip |  |
| apache_tomcat.access.http.ident | Remote logical username from identd. | keyword |  |
| apache_tomcat.access.http.useragent | The user id of the authenticated user requesting the page (if HTTP authentication is used). | keyword |  |
| apache_tomcat.access.ip.local | Local IP address. | ip |  |
| apache_tomcat.access.response_time | Response time of the endpoint. | double | s |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| destination.bytes | Bytes sent from the destination to the source. | long |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |  |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |  |
| http.request.referrer | Referrer for this HTTP request. | keyword |  |
| http.response.status_code | HTTP response status code. | long |  |
| http.version | HTTP version. | keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| log.offset | Log offset. | long |  |
| related.ip | All of the IPs seen on your event. | ip |  |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |  |
| tags | List of keywords used to tag each event. | keyword |  |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |  |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |  |
| url.original.text | Multi-field of `url.original`. | match_only_text |  |
| url.path | Path of the request, such as "/search". | wildcard |  |
| user_agent.device.name | Name of the device. | keyword |  |
| user_agent.name | Name of the user agent. | keyword |  |
| user_agent.original | Unparsed user_agent string. | keyword |  |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |  |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |  |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |  |
| user_agent.os.name | Operating system name, without the version. | keyword |  |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |  |
| user_agent.os.version | Operating system version as a raw string. | keyword |  |
| user_agent.version | Version of the user agent. | keyword |  |


### Catalina

This is the `Catalina` data stream. This data stream collects logs related to the startup and shutdown of the Apache Tomcat application server, the deployment of new applications, or the failure of one or more subsystems.

An example event for `catalina` looks as following:

```json
{
    "@timestamp": "2023-05-05T11:09:44.042Z",
    "agent": {
        "ephemeral_id": "58b8cc5c-7b20-44e5-b16d-5964d7fd38e6",
        "id": "3fe5ea83-99fe-41e9-bab5-bb8b1ca208a7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.0"
    },
    "apache_tomcat": {
        "catalina": {
            "subsystem": "main"
        }
    },
    "data_stream": {
        "dataset": "apache_tomcat.catalina",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "3fe5ea83-99fe-41e9-bab5-bb8b1ca208a7",
        "snapshot": false,
        "version": "8.7.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "apache_tomcat.catalina",
        "ingested": "2023-05-05T11:10:38Z",
        "kind": "event",
        "module": "apache_tomcat",
        "original": "05-May-2023 11:09:44.042 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server version name:   Apache Tomcat/10.1.5",
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/catalina.2023-05-05.log"
        },
        "level": "info",
        "offset": 0
    },
    "message": "org.apache.catalina.startup.VersionLoggerListener.log Server version name:   Apache Tomcat/10.1.5",
    "tags": [
        "preserve_original_event",
        "forwarded",
        "apache_tomcat-catalina"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_tomcat.catalina.subsystem | Indicates Apache Tomcat’s subsystem or the type of the module that was the source of the message. For example, RBPM or Java Messaging Service (JMS). | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| error.stack_trace | The stack trace of this error in plain text. | wildcard |
| error.stack_trace.text | Multi-field of `error.stack_trace`. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |

