# PHP-FPM Integration

## Overview

PHP-FPM (FastCGI Process Manager) is a web tool used to speed up the performance of a website. It is much faster than traditional CGI based methods and has the ability to handle tremendous loads simultaneously.

## Data streams

The PHP-FPM integration collects metrics data.

Metrics give you insight into the statistics of the PHP-FPM. Metrics data streams collected by the PHP-FPM integration include [process](https://www.php.net/manual/en/fpm.status.php#:~:text=Per%2Dprocess%20information%20%2D%20only%20displayed%20in%20full%20output%20mode) so that the user can monitor and troubleshoot the performance of the PHP-FPM instances.

Note:
- Users can monitor and see the metrics inside the ingested documents for PHP-FPM in the logs-* index pattern from `Discover`.

## Compatibility

This integration has been tested against `v8.2` and `v8.1` standalone versions of PHP-FPM.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from PHP-FPM, you must know the host(s) and status path of the PHP-FPM instance.

Host configuration format: `http[s]://host[:port]`

Example host configuration: `http://localhost:8080`

Status path configuration format: `/path`

Example Status path configuration: `/status` 

## Metrics reference

### Process

This is the `process` data stream. `process` data stream collects metrics like request duration, content length, process state, etc.

An example event for `process` looks as following:

```json
{
    "@timestamp": "2022-11-15T14:01:31.755Z",
    "agent": {
        "ephemeral_id": "c505ab2b-ef2e-45aa-8ee4-998433179139",
        "id": "eb39489c-ee82-4bd4-b2d3-31f09610ca2e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "data_stream": {
        "dataset": "php_fpm.process",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "eb39489c-ee82-4bd4-b2d3-31f09610ca2e",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web",
            "configuration",
            "process"
        ],
        "created": "2022-11-15T14:01:31.755Z",
        "dataset": "php_fpm.process",
        "ingested": "2022-11-15T14:01:35Z",
        "kind": "event",
        "module": "php_fpm",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "body": {
                "bytes": 0
            },
            "method": "GET"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "php_fpm": {
        "process": {
            "pool": {
                "name": "www"
            },
            "request": {
                "count": 2,
                "duration": 186,
                "last": {
                    "cpu": {
                        "pct": 0
                    },
                    "memory": 0
                }
            },
            "script": "-",
            "start_since": 6,
            "start_time": 1668520885,
            "state": "Running"
        }
    },
    "process": {
        "pid": 33
    },
    "tags": [
        "php_fpm-process",
        "forwarded"
    ],
    "url": {
        "original": "/status?json\u0026full"
    },
    "user": {
        "name": "-"
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
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| http.request.body.bytes | Size in bytes of the request body. | long |  |  |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |
| php_fpm.process.pool.name | The name of the FPM process pool. | keyword |  |  |
| php_fpm.process.request.count | The total number of requests served. | long |  | counter |
| php_fpm.process.request.duration | The total time in seconds spent serving requests. | long | s | counter |
| php_fpm.process.request.last.cpu.pct | The %cpu of the last request. This will be 0 if the process is not Idle because the calculation is done when the request processing is complete. | long | percent | gauge |
| php_fpm.process.request.last.memory | The maximum amount of memory consumed by the last request. This will be 0 if the process is not Idle because the calculation is done when the request processing is complete. | long |  | gauge |
| php_fpm.process.script | The full path of the script executed by the last request. This will be '-' if not applicable (eg. status page requests). | keyword |  |  |
| php_fpm.process.start_since | The number of seconds since the process started. | long | s | counter |
| php_fpm.process.start_time | The date/time at which the process started. | long |  |  |
| php_fpm.process.state | The state of the process. | keyword |  |  |
| process.pid | Process id. | long |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |  |  |
| url.original.text | Multi-field of `url.original`. | match_only_text |  |  |
| user.name | Short name or login of the user. | keyword |  |  |
| user.name.text | Multi-field of `user.name`. | match_only_text |  |  |
