# IBM MQ integration

The IBM MQ Integration is used to fetch observability data from [IBM MQ web endpoints](https://www.ibm.com/docs/en/ibm-mq) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `IBM MQ v9.1` and `IBM MQ v9.2`.

## Requirements

In order to ingest data from IBM MQ:
- User should specify the path of IBM MQ Queue Manager Error logs. (default paths: `/var/mqm/errors/*.LOG` and `/var/mqm/qmgrs/*/errors/*.LOG`)

## Logs

### Queue Manager Error logs

The `errorlog` data stream collects [Error logs of Queue Manager](https://www.site24x7.com/help/log-management/ibm-mq-error-logs.html) which include the description, action, explanation and code of the error.

An example event for `errorlog` looks as following:

```json
{
    "@timestamp": "2022-06-29T08:23:34.385Z",
    "agent": {
        "ephemeral_id": "12f21cf2-6df4-459c-8ce2-413e761943ae",
        "id": "1a4dbf12-3b5c-45ea-9256-3c1754b52588",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "ibmmq.errorlog",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "1a4dbf12-3b5c-45ea-9256-3c1754b52588",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-06-29T08:23:59.009Z",
        "dataset": "ibmmq.errorlog",
        "ingested": "2022-06-29T08:24:02Z",
        "kind": "event",
        "module": "ibmmq",
        "type": "error"
    },
    "host": {
        "hostname": "20c2d61f227a",
        "name": "docker-fleet-agent"
    },
    "ibmmq": {
        "errorlog": {
            "error": {
                "action": "Host Info :- Linux 3.10.0-1160.59.1.el7.x86_64 (MQ Linux (x86-64 platform) 64-bit) Installation :- /opt/mqm (Installation1) Version :- 9.2.4.0 (p924-L211105.DE) ACTION: None.",
                "code": "AMQ6287I",
                "description": "IBM MQ V9.2.4.0 (p924-L211105.DE).",
                "explanation": "IBM MQ system"
            },
            "insert": {
                "comment": [
                    "Linux 3.10.0-1160.59.1.el7.x86_64 (MQ Linux (x86-64 platform) 64-bit)",
                    "/opt/mqm (Installation1)",
                    "9.2.4.0 (p924-L211105.DE)"
                ]
            },
            "installation": "Installation1"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/AMQERR01.LOG"
        },
        "flags": [
            "multiline"
        ],
        "offset": 0
    },
    "process": {
        "pid": 61.1,
        "title": "crtmqm"
    },
    "service": {
        "version": "9.2.4.0"
    },
    "tags": [
        "forwarded",
        "ibmmq-errorlog"
    ],
    "user": {
        "name": "root"
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
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| ibmmq.errorlog.error.action | Defines what to do when the error occurs. | keyword |
| ibmmq.errorlog.error.code | Error code. | keyword |
| ibmmq.errorlog.error.description | Error description. | text |
| ibmmq.errorlog.error.explanation | Explains the error in more detail. | keyword |
| ibmmq.errorlog.insert.arith | Changing content based on error.id. | keyword |
| ibmmq.errorlog.insert.comment | Changing content based on error.id. | keyword |
| ibmmq.errorlog.installation | This is the installation name which can be given at installation time. Each installation of IBM MQ on UNIX, Linux, and Windows, has a unique identifier known as an installation name. The installation name is used to associate things such as queue managers and configuration files with an installation. | keyword |
| ibmmq.errorlog.log_timestamp | Error log occur time. | keyword |
| ibmmq.errorlog.queue_manager | Name of the queue manager. Queue managers provide queuing services to applications, and manages the queues that belong to them. | keyword |
| input.type | The input type from which the event was generated. This field is set to the value specified for the type option in the input section of the Filebeat config file. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | This field contains the flags of the event. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | The file offset the reported line starts at. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

