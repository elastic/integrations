# Kibana

The Kibana integration collects events from your [Kibana](https://www.elastic.co/guide/en/kibana/current/introduction.html) instance.

## Configuration parameters

If the Kibana instance is using a basepath in its URL, you must set the `basepath` setting for this integration with the same value.

## Compatibility

The `kibana` package works with Kibana 8.10.0 and later.

## Usage for Stack Monitoring

The `kibana` package can be used to collect metrics shown in our Stack Monitoring
UI in Kibana.

**Note**: Using this integration package will require elasticsearch to be monitored as well in order to see the data in Stack Monitoring UI. If the elasticsearch data is not collected and only Kibana is monitored the Stack monitoring UI won't show the Kibana data.

## Logs

### Audit

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| input.type | The input type from which the event was generated. This field is set to the value specified for the type option in the input section of the Filebeat config file. | keyword |
| kibana.add_to_spaces | The set of space ids that a saved object was shared to. | keyword |
| kibana.authentication_provider | The authentication provider associated with a login event. | keyword |
| kibana.authentication_realm | The Elasticsearch authentication realm name which fulfilled a login event. | keyword |
| kibana.authentication_type | The authentication provider type associated with a login event. | keyword |
| kibana.delete_from_spaces | The set of space ids that a saved object was removed from. | keyword |
| kibana.lookup_realm | The Elasticsearch lookup realm which fulfilled a login event. | keyword |
| kibana.saved_object.id | The id of the saved object associated with this event. | keyword |
| kibana.saved_object.name | The name of the saved object associated with this event. | keyword |
| kibana.saved_object.type | The type of the saved object associated with this event. | keyword |
| kibana.session_id | The ID of the user session associated with this event. Each login attempt results in a unique session id. | keyword |
| kibana.space_id | The id of the space associated with this event. | keyword |
| labels.application |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | The file offset the reported line starts at. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.pid | Process id. | long |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| service.node.roles | Roles of a service node. This allows for distinction between different running roles of the same service. In the case of Kibana, the `service.node.role` could be `ui` or `background_tasks` or both. In the case of Elasticsearch, the `service.node.role` could be `master` or `data` or both. Other services could use this to distinguish between a `web` and `worker` role running as part of the service. | keyword |
| trace.id | Unique identifier of the trace. A trace groups multiple events like transactions that belong together. For example, a user request handled by multiple inter-connected services. | keyword |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |


### Log

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.ip | Host ip addresses. | ip |
| http.request.headers |  | flattened |
| http.request.id | A unique identifier for each HTTP request to correlate logs between clients and servers in transactions. The id may be contained in a non-standard HTTP header, such as `X-Request-ID` or `X-Correlation-ID`. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.mime_type | Mime type of the body of the request. This value must only be populated based on the content of the request body, not on the `Content-Type` header. Comparing the mime type of a request with the request's Content-Type header can be helpful in detecting threats or misconfigured clients. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.headers |  | flattened |
| http.response.responseTime |  | long |
| http.response.status_code | HTTP response status code. | long |
| input.type | The input type from which the event was generated. This field is set to the value specified for the type option in the input section of the Filebeat config file | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | The file offset the reported line starts at. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.eventLoopDelay |  | unsigned_long |
| process.eventLoopDelayHistogram.50 |  | long |
| process.eventLoopDelayHistogram.95 |  | long |
| process.eventLoopDelayHistogram.99 |  | long |
| process.eventLoopUtilization.active |  | double |
| process.eventLoopUtilization.idle |  | double |
| process.eventLoopUtilization.utilization |  | double |
| process.memory.heap.usedInBytes |  | long |
| process.pid | Process id. | long |
| process.uptime | Seconds the process has been up. | long |
| service.node.roles | Roles of a service node. This allows for distinction between different running roles of the same service. In the case of Kibana, the `service.node.role` could be `ui` or `background_tasks` or both. In the case of Elasticsearch, the `service.node.role` could be `master` or `data` or both. Other services could use this to distinguish between a `web` and `worker` role running as part of the service. | keyword |
| session_id |  | keyword |
| tags | List of keywords used to tag each event. | keyword |
| trace.id | Unique identifier of the trace. A trace groups multiple events like transactions that belong together. For example, a user request handled by multiple inter-connected services. | keyword |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |


## HTTP Metrics

### Background task utilization

This data stream uses the `/api/task_manager/_background_task_utilization` API of Kibana, which is available starting in 8.9.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| kibana.background_task_utilization.last_update |  | date |
| kibana.background_task_utilization.process_uuid |  | keyword |
| kibana.background_task_utilization.stats.timestamp |  | date |
| kibana.background_task_utilization.stats.value.load |  | long |
| kibana.background_task_utilization.timestamp |  | date |
| kibana_stats.kibana.uuid |  | alias |
| kibana_stats.kibana.version |  | alias |
| kibana_stats.timestamp |  | alias |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| timestamp |  | alias |


An example event for `background_task_utilization` looks as following:

```json
{
    "@timestamp": "2023-05-11T16:41:30.793Z",
    "agent": {
        "ephemeral_id": "a8cb0dfc-d83d-4928-8836-decae307ed1a",
        "id": "48b3ac4e-1e5d-4c6c-a76a-6c18ae017df9",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "kibana.background_task_utilization",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "48b3ac4e-1e5d-4c6c-a76a-6c18ae017df9",
        "snapshot": true,
        "version": "8.9.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "kibana.background_task_utilization",
        "duration": 23467000,
        "ingested": "2023-05-11T16:41:31Z",
        "module": "http"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "2928cd5a7c374273b53f983d5bd5a3c9",
        "ip": [
            "172.26.0.7"
        ],
        "mac": [
            "02-42-AC-1A-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.49-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "kibana": {
        "background_task_utilization": {
            "last_update": "2023-05-11T16:41:27.977Z",
            "process_uuid": "5547afe7-b651-4c95-b2e4-dc23ac1e5a8d",
            "stats": {
                "timestamp": "2023-05-11T16:41:27.977Z",
                "value": {
                    "load": 4
                }
            },
            "timestamp": "2023-05-11T16:41:30.813Z"
        }
    },
    "metricset": {
        "name": "json",
        "period": 10000
    },
    "service": {
        "address": "https://kibana:5601/api/task_manager/_background_task_utilization",
        "type": "http"
    }
}
```

### Task manager metrics

This data stream uses the `/api/task_manager/metrics` API of Kibana, which is available starting in 8.10.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| kibana.task_manager_metrics.last_update |  | date |
| kibana.task_manager_metrics.metrics.task_claim.timestamp |  | date |
| kibana.task_manager_metrics.metrics.task_claim.value.duration |  | histogram |
| kibana.task_manager_metrics.metrics.task_claim.value.success |  | long |
| kibana.task_manager_metrics.metrics.task_claim.value.total |  | long |
| kibana.task_manager_metrics.metrics.task_run.timestamp |  | date |
| kibana.task_manager_metrics.metrics.task_run.value.by_type.\*.success |  | long |
| kibana.task_manager_metrics.metrics.task_run.value.by_type.\*.total |  | long |
| kibana.task_manager_metrics.metrics.task_run.value.overall.success |  | long |
| kibana.task_manager_metrics.metrics.task_run.value.overall.total |  | long |
| kibana.task_manager_metrics.process_uuid |  | keyword |
| kibana.task_manager_metrics.timestamp |  | date |
| kibana_stats.kibana.uuid |  | alias |
| kibana_stats.kibana.version |  | alias |
| kibana_stats.timestamp |  | alias |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| timestamp |  | alias |


An example event for `task_manager` looks as following:

```json
{
    "@timestamp": "2023-08-23T15:16:50.293Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "8e1f023e-e70d-40a7-905a-f1ff1271b631",
        "type": "metricbeat",
        "ephemeral_id": "7a40c3bb-4628-496b-ba5f-7f0fb82e1767",
        "version": "8.10.0"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kibana.task_manager_metrics"
    },
    "service": {
        "address": "https://kibana:5601/api/task_manager/metrics",
        "type": "http"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.15.49-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "family": "debian",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.23.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "0d43b8a597974fa28645b1e16ce2db8d",
        "mac": [
            "02-42-AC-17-00-07"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "8e1f023e-e70d-40a7-905a-f1ff1271b631",
        "version": "8.10.0",
        "snapshot": true
    },
    "metricset": {
        "period": 10000,
        "name": "json"
    },
    "http": {},
    "kibana": {
        "task_manager_metrics": {
            "last_update": "2023-08-23T15:16:49.213Z",
            "process_uuid": "2b4126d2-f102-4d6c-9070-9763d142ed14",
            "metrics": {
                "task_run": {
                    "value": {
                        "overall": {
                            "total": 1,
                            "success": 1
                        },
                        "by_type": {
                            "cases-telemetry-task": {
                                "total": 0,
                                "success": 0
                            },
                            "apm-telemetry-task": {
                                "total": 0,
                                "success": 0
                            },
                            "osquery:telemetry-saved-queries": {
                                "total": 0,
                                "success": 0
                            },
                            "security:telemetry-detection-rules": {
                                "total": 0,
                                "success": 0
                            },
                            "alerting_telemetry": {
                                "total": 0,
                                "success": 0
                            },
                            "alerts_invalidate_api_keys": {
                                "total": 0,
                                "success": 0
                            },
                            "security:endpoint-diagnostics": {
                                "total": 0,
                                "success": 0
                            },
                            "endpoint:user-artifact-packager": {
                                "total": 0,
                                "success": 0
                            },
                            "security:telemetry-filterlist-artifact": {
                                "total": 0,
                                "success": 0
                            },
                            "session_cleanup": {
                                "total": 0,
                                "success": 0
                            },
                            "osquery:telemetry-configs": {
                                "total": 0,
                                "success": 0
                            },
                            "security:telemetry-timelines": {
                                "total": 0,
                                "success": 0
                            },
                            "Fleet-Usage-Sender": {
                                "total": 0,
                                "success": 0
                            },
                            "security:endpoint-meta-telemetry": {
                                "total": 0,
                                "success": 0
                            },
                            "ML:saved-objects-sync": {
                                "total": 0,
                                "success": 0
                            },
                            "security:telemetry-prebuilt-rule-alerts": {
                                "total": 0,
                                "success": 0
                            },
                            "osquery:telemetry-packs": {
                                "total": 0,
                                "success": 0
                            },
                            "dashboard_telemetry": {
                                "total": 0,
                                "success": 0
                            },
                            "Fleet-Usage-Logger": {
                                "total": 0,
                                "success": 0
                            },
                            "security:telemetry-lists": {
                                "total": 0,
                                "success": 0
                            },
                            "actions_telemetry": {
                                "total": 0,
                                "success": 0
                            },
                            "apm-source-map-migration-task": {
                                "total": 0,
                                "success": 0
                            },
                            "security:telemetry-configuration": {
                                "total": 0,
                                "success": 0
                            },
                            "endpoint:metadata-check-transforms-task": {
                                "total": 0,
                                "success": 0
                            },
                            "fleet:check-deleted-files-task": {
                                "total": 0,
                                "success": 0
                            },
                            "alerting_health_check": {
                                "total": 0,
                                "success": 0
                            },
                            "reports:monitor": {
                                "total": 1,
                                "success": 1
                            }
                        }
                    },
                    "timestamp": "2023-08-23T15:16:46.327Z"
                },
                "task_claim": {
                    "value": {
                        "duration": {
                            "counts": [
                                3
                            ],
                            "values": [
                                100
                            ]
                        },
                        "total": 3,
                        "success": 3
                    },
                    "timestamp": "2023-08-23T15:16:49.213Z"
                }
            },
            "timestamp": "2023-08-23T15:16:49.213Z"
        }
    },
    "event": {
        "duration": 19616583,
        "agent_id_status": "verified",
        "ingested": "2023-08-23T15:16:51Z",
        "module": "http",
        "dataset": "kibana.task_manager_metrics"
    }
}
```

## Metrics

### Stats

Stats data stream uses the stats endpoint of Kibana, which is available in 6.4 by default.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| kibana.elasticsearch.cluster.id |  | keyword |
| kibana.stats.concurrent_connections | Number of client connections made to the server. Note that browsers can send multiple simultaneous connections to request multiple server assets at once, and they can re-use established connections. | long |
| kibana.stats.elasticsearch_client.total_active_sockets |  | long |
| kibana.stats.elasticsearch_client.total_idle_sockets |  | long |
| kibana.stats.elasticsearch_client.total_queued_requests |  | long |
| kibana.stats.host.name | Kibana instance hostname | keyword |
| kibana.stats.index | Name of Kibana's internal index | keyword |
| kibana.stats.kibana.status |  | keyword |
| kibana.stats.name | Kibana instance name | keyword |
| kibana.stats.os.cgroup_memory.current_in_bytes |  | long |
| kibana.stats.os.cgroup_memory.swap_current_in_bytes |  | long |
| kibana.stats.os.cpuacct.control_group |  | keyword |
| kibana.stats.os.cpuacct.usage_nanos |  | long |
| kibana.stats.os.distro |  | keyword |
| kibana.stats.os.distroRelease |  | keyword |
| kibana.stats.os.load.15m |  | half_float |
| kibana.stats.os.load.1m |  | half_float |
| kibana.stats.os.load.5m |  | half_float |
| kibana.stats.os.memory.free_in_bytes |  | long |
| kibana.stats.os.memory.total_in_bytes |  | long |
| kibana.stats.os.memory.used_in_bytes |  | long |
| kibana.stats.os.platform |  | keyword |
| kibana.stats.os.platformRelease |  | keyword |
| kibana.stats.process.event_loop_delay.ms | Event loop delay in milliseconds | scaled_float |
| kibana.stats.process.event_loop_utilization.active |  | double |
| kibana.stats.process.event_loop_utilization.idle |  | double |
| kibana.stats.process.event_loop_utilization.utilization |  | double |
| kibana.stats.process.memory.array_buffers.bytes |  | long |
| kibana.stats.process.memory.external.bytes |  | long |
| kibana.stats.process.memory.heap.size_limit.bytes | Max. old space size allocated to Node.js process, in bytes | long |
| kibana.stats.process.memory.heap.total.bytes | Total heap allocated to process in bytes | long |
| kibana.stats.process.memory.heap.uptime.ms | Uptime of process in milliseconds | long |
| kibana.stats.process.memory.heap.used.bytes | Heap used by process in bytes | long |
| kibana.stats.process.memory.resident_set_size.bytes |  | long |
| kibana.stats.process.uptime.ms |  | long |
| kibana.stats.request.disconnects | Number of requests that were disconnected | long |
| kibana.stats.request.total | Total number of requests | long |
| kibana.stats.response_time.avg.ms | Average response time in milliseconds | long |
| kibana.stats.response_time.max.ms | Maximum response time in milliseconds | long |
| kibana.stats.snapshot | Whether the Kibana build is a snapshot build | boolean |
| kibana.stats.status | Kibana instance's health status | keyword |
| kibana.stats.transport_address | Address where data about this service was collected from. | keyword |
| kibana.stats.usage.index |  | keyword |
| kibana_stats.concurrent_connections |  | alias |
| kibana_stats.kibana.response_time.max |  | alias |
| kibana_stats.kibana.status |  | alias |
| kibana_stats.kibana.uuid |  | alias |
| kibana_stats.kibana.version |  | alias |
| kibana_stats.os.load.15m |  | alias |
| kibana_stats.os.load.1m |  | alias |
| kibana_stats.os.load.5m |  | alias |
| kibana_stats.os.memory.free_in_bytes |  | alias |
| kibana_stats.process.event_loop_delay |  | alias |
| kibana_stats.process.memory.heap.size_limit |  | alias |
| kibana_stats.process.memory.resident_set_size_in_bytes |  | alias |
| kibana_stats.process.uptime_in_millis |  | alias |
| kibana_stats.requests.disconnects |  | alias |
| kibana_stats.requests.total |  | alias |
| kibana_stats.response_times.average |  | alias |
| kibana_stats.response_times.max |  | alias |
| kibana_stats.timestamp |  | alias |
| process.pid | Process id. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| timestamp |  | alias |


An example event for `stats` looks as following:

```json
{
    "@timestamp": "2022-10-11T19:06:28.320Z",
    "agent": {
        "ephemeral_id": "f796f6ed-21e4-48d5-bb4f-4cc69b3fb3f2",
        "id": "b3e85606-c252-4a5e-af71-7b138302dbd9",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "kibana.stack_monitoring.stats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "b3e85606-c252-4a5e-af71-7b138302dbd9",
        "snapshot": true,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "kibana.stack_monitoring.stats",
        "duration": 57404375,
        "ingested": "2022-10-11T19:06:29Z",
        "module": "kibana"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "b6bc6723e51b43959ce07f0c3105c72d",
        "ip": [
            "172.31.0.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "kibana": {
        "elasticsearch": {
            "cluster": {
                "id": "II5HA1VCQPGB4bQLCi5yZw"
            }
        },
        "stats": {
            "concurrent_connections": 0,
            "host": {
                "name": "0.0.0.0"
            },
            "index": ".kibana",
            "name": "kibana",
            "os": {
                "distro": "Ubuntu",
                "distroRelease": "Ubuntu-20.04",
                "load": {
                    "15m": 3.1,
                    "1m": 4.29,
                    "5m": 3.7
                },
                "memory": {
                    "free_in_bytes": 5613236224,
                    "total_in_bytes": 12544004096,
                    "used_in_bytes": 6930767872
                },
                "platform": "linux",
                "platformRelease": "linux-5.10.124-linuxkit",
                "cpuacct": {
                    "control_group": "cgroup",
                    "usage_nanos": 56132224
                },
                "cgroup_memory": {
                    "current_in_bytes": 60869566,
                    "swap_current_in_bytes": 65374608
                }
            },
            "process": {
                "event_loop_delay": {
                    "ms": 10.846537460869566
                },
                "memory": {
                    "heap": {
                        "size_limit": {
                            "bytes": 2197815296
                        },
                        "total": {
                            "bytes": 608399360
                        },
                        "used": {
                            "bytes": 295489000
                        }
                    },
                    "resident_set_size": {
                        "bytes": 716869632
                    },
                    "array_buffers": {
                        "bytes": 2197869632
                    },
                    "external": {
                        "bytes": 4890295460
                    }
                },
                "uptime": {
                    "ms": 25686
                }
            },
            "request": {
                "disconnects": 0,
                "total": 7
            },
            "response_time": {
                "avg": {
                    "ms": 13
                },
                "max": {
                    "ms": 48
                }
            },
            "snapshot": true,
            "status": "green",
            "transport_address": "0.0.0.0:5601"
        }
    },
    "metricset": {
        "name": "stats",
        "period": 10000
    },
    "process": {
        "pid": 7
    },
    "service": {
        "address": "http://elastic-package-service-kibana-1:5601/api/stats?extended=true",
        "id": "d67ef18d-cefc-4ca5-b844-123adf3a0eb7",
        "type": "kibana",
        "version": "8.5.0"
    }
}
```

### Status

This status endpoint is available in 6.0 by default and can be enabled in Kibana >= 5.4 with the config option `status.v6ApiFormat: true`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| kibana.status.metrics.concurrent_connections | Current concurrent connections. | long |
| kibana.status.metrics.requests.disconnects | Total number of disconnected connections. | long |
| kibana.status.metrics.requests.total | Total number of connections. | long |
| kibana.status.name | Kibana instance name. | keyword |
| kibana.status.status.overall.state | Kibana overall state. | keyword |
| service.address | Address where data about this service was collected from. | keyword |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |


An example event for `status` looks as following:

```json
{
    "@timestamp": "2022-10-11T19:07:58.348Z",
    "agent": {
        "ephemeral_id": "f796f6ed-21e4-48d5-bb4f-4cc69b3fb3f2",
        "id": "b3e85606-c252-4a5e-af71-7b138302dbd9",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "kibana.stack_monitoring.status",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "b3e85606-c252-4a5e-af71-7b138302dbd9",
        "snapshot": true,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "kibana.stack_monitoring.status",
        "duration": 21930208,
        "ingested": "2022-10-11T19:07:59Z",
        "module": "kibana"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "b6bc6723e51b43959ce07f0c3105c72d",
        "ip": [
            "172.31.0.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "kibana": {
        "status": {
            "metrics": {
                "concurrent_connections": 0,
                "requests": {
                    "disconnects": 0,
                    "total": 6
                }
            },
            "name": "kibana",
            "status": {
                "overall": {}
            }
        }
    },
    "metricset": {
        "name": "status",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-kibana-1:5601/api/status",
        "id": "40f3cc0f-ff7c-4e7e-a470-bbdb124a32ca",
        "name": "kibana",
        "type": "kibana",
        "version": "8.5.0"
    }
}
```

### Cluster actions

Cluster actions metrics documentation

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| kibana.cluster_actions.overdue.count |  | long |
| kibana.cluster_actions.overdue.delay.p50 |  | float |
| kibana.cluster_actions.overdue.delay.p99 |  | float |
| kibana.elasticsearch.cluster.id |  | keyword |
| kibana_stats.kibana.uuid |  | alias |
| kibana_stats.kibana.version |  | alias |
| kibana_stats.timestamp |  | alias |
| process.pid | Process id. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| timestamp |  | alias |


An example event for `cluster_actions` looks as following:

```json
{
    "@timestamp": "2022-10-11T13:16:56.271Z",
    "agent": {
        "ephemeral_id": "928bf66e-bd3d-44d0-9cd8-8896033ea65f",
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "kibana.stack_monitoring.cluster_actions",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "snapshot": true,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "kibana.stack_monitoring.cluster_actions",
        "duration": 29863417,
        "ingested": "2022-10-11T13:16:57Z",
        "module": "kibana"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "b6bc6723e51b43959ce07f0c3105c72d",
        "ip": [
            "192.168.0.7"
        ],
        "mac": [
            "02-42-C0-A8-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "kibana": {
        "cluster_actions": {
            "overdue": {
                "count": 0,
                "delay": {
                    "p50": 0,
                    "p99": 0
                }
            }
        },
        "elasticsearch.cluster.id": "4tCLrloiQWS6rLAX6pkQCA"
    },
    "metricset": {
        "name": "cluster_actions",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-kibana-1:5601/api/monitoring_collection/cluster_actions",
        "type": "kibana"
    },
    "service.address": "0.0.0.0:5601",
    "service.id": "5308cf43-e91a-4a98-83b2-38cf29f90984",
    "service.version": "8.5.0"
}
```

### Cluster rules

Cluster rules metrics

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| kibana.cluster_rules.overdue.count |  | long |
| kibana.cluster_rules.overdue.delay.p50 |  | float |
| kibana.cluster_rules.overdue.delay.p99 |  | float |
| kibana.elasticsearch.cluster.id |  | keyword |
| kibana_stats.kibana.uuid |  | alias |
| kibana_stats.kibana.version |  | alias |
| kibana_stats.timestamp |  | alias |
| process.pid | Process id. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| timestamp |  | alias |


An example event for `cluster_rules` looks as following:

```json
{
    "@timestamp": "2022-10-11T13:18:21.819Z",
    "agent": {
        "ephemeral_id": "928bf66e-bd3d-44d0-9cd8-8896033ea65f",
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "kibana.stack_monitoring.cluster_rules",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "snapshot": true,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "kibana.stack_monitoring.cluster_rules",
        "duration": 36973542,
        "ingested": "2022-10-11T13:18:22Z",
        "module": "kibana"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "b6bc6723e51b43959ce07f0c3105c72d",
        "ip": [
            "192.168.0.7"
        ],
        "mac": [
            "02-42-C0-A8-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "kibana": {
        "cluster_rules": {
            "overdue": {
                "count": 0,
                "delay": {
                    "p50": 0,
                    "p99": 0
                }
            }
        },
        "elasticsearch.cluster.id": "-OYej1hvQty3Au1KnzPMBQ"
    },
    "metricset": {
        "name": "cluster_rules",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-kibana-1:5601/api/monitoring_collection/cluster_rules",
        "type": "kibana"
    },
    "service.address": "0.0.0.0:5601",
    "service.id": "2cefd6b5-7e44-4d47-be34-b0cec003629d",
    "service.version": "8.5.0"
}
```

### Node actions

Node actions metrics

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| kibana.elasticsearch.cluster.id |  | keyword |
| kibana.node_actions.executions |  | long |
| kibana.node_actions.failures |  | long |
| kibana.node_actions.timeouts |  | long |
| kibana_stats.kibana.uuid |  | alias |
| kibana_stats.kibana.version |  | alias |
| kibana_stats.timestamp |  | alias |
| process.pid | Process id. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| timestamp |  | alias |


An example event for `node_actions` looks as following:

```json
{
    "@timestamp": "2022-10-11T13:21:36.785Z",
    "agent": {
        "ephemeral_id": "4e2e71ae-5cc0-4f0b-aad9-212bfcdd57d3",
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "kibana.stack_monitoring.node_actions",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "snapshot": true,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "kibana.stack_monitoring.node_actions",
        "duration": 13700542,
        "ingested": "2022-10-11T13:21:37Z",
        "module": "kibana"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "b6bc6723e51b43959ce07f0c3105c72d",
        "ip": [
            "192.168.0.7"
        ],
        "mac": [
            "02-42-C0-A8-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "kibana": {
        "elasticsearch.cluster.id": "Wm8-GgnLRcOMeOxcj_FKqA",
        "node_actions": {
            "executions": 0,
            "failures": 0,
            "timeouts": 0
        }
    },
    "metricset": {
        "name": "node_actions",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-kibana-1:5601/api/monitoring_collection/node_actions",
        "type": "kibana"
    },
    "service.address": "0.0.0.0:5601",
    "service.id": "267b8a74-bc40-451f-bacb-ebca6ef242ab",
    "service.version": "8.5.0"
}
```

### Node rules

Node rules metrics

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| kibana.elasticsearch.cluster.id |  | keyword |
| kibana.node_rules.executions |  | long |
| kibana.node_rules.failures |  | long |
| kibana.node_rules.timeouts |  | long |
| kibana_stats.kibana.uuid |  | alias |
| kibana_stats.kibana.version |  | alias |
| kibana_stats.timestamp |  | alias |
| process.pid | Process id. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| timestamp |  | alias |


An example event for `node_rules` looks as following:

```json
{
    "@timestamp": "2022-10-11T13:23:15.907Z",
    "agent": {
        "ephemeral_id": "4e2e71ae-5cc0-4f0b-aad9-212bfcdd57d3",
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "kibana.stack_monitoring.node_rules",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "snapshot": true,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "kibana.stack_monitoring.node_rules",
        "duration": 11258084,
        "ingested": "2022-10-11T13:23:16Z",
        "module": "kibana"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "b6bc6723e51b43959ce07f0c3105c72d",
        "ip": [
            "192.168.0.7"
        ],
        "mac": [
            "02-42-C0-A8-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "kibana": {
        "elasticsearch.cluster.id": "A0ZRwT9JTTW4XHNhUd0hUg",
        "node_rules": {
            "executions": 0,
            "failures": 0,
            "timeouts": 0
        }
    },
    "metricset": {
        "name": "node_rules",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-kibana-1:5601/api/monitoring_collection/node_rules",
        "type": "kibana"
    },
    "service.address": "0.0.0.0:5601",
    "service.id": "9d55da50-cf7c-49c1-9328-a164de23d186",
    "service.version": "8.5.0"
}
```
