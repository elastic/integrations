# PHP-FPM Integration

## Overview

PHP-FPM (FastCGI Process Manager) is a web tool used to speed up the performance of a website. It is much faster than traditional CGI based methods and has the ability to handle tremendous loads simultaneously.

## Data streams

The PHP-FPM integration collects metrics data.

Metrics give you insight into the statistics of the PHP-FPM. Metrics data streams collected by the PHP-FPM integration include [pool](https://www.php.net/manual/en/fpm.status.php#:~:text=Basic%20information%20%2D%20Always%20displayed%20on%20the%20status%20page) so that the user could monitor and troubleshoot the performance of the PHP-FPM instances.

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

### Pool

This is the `pool` data stream. `pool` data stream collects metrics related to the setup and contents of the FPM status page.

An example event for `pool` looks as following:

```json
{
    "@timestamp": "2022-11-08T12:28:32.010Z",
    "agent": {
        "ephemeral_id": "bc8a33f5-b8f3-4c39-a808-c0145638ed96",
        "id": "97c2a1e6-10a8-4398-a12b-d8c1a6a01750",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "data_stream": {
        "dataset": "php_fpm.pool",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "97c2a1e6-10a8-4398-a12b-d8c1a6a01750",
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
        "created": "2022-11-08T12:28:32.010Z",
        "dataset": "php_fpm.pool",
        "ingested": "2022-11-08T12:28:35Z",
        "kind": "event",
        "module": "php_fpm",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "php_fpm": {
        "pool": {
            "connections": {
                "accepted": 1,
                "listen_queue": {
                    "max_size": 128,
                    "requests": {
                        "max": 0
                    }
                },
                "queued": 0
            },
            "name": "www",
            "process_manager": {
                "type": "ondemand"
            },
            "processes": {
                "active": {
                    "count": 1,
                    "max": 1
                },
                "children_reached": {
                    "max": 0
                },
                "count": 1,
                "idle": 0
            },
            "slow_requests": 0,
            "start_since": 22,
            "start_time": 1667910490
        }
    },
    "tags": [
        "php_fpm-pool",
        "forwarded"
    ]
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
| input.type | Type of Filebeat input. | keyword |  |  |
| php_fpm.pool.connections.accepted | The total number of accepted connections. | long |  | counter |
| php_fpm.pool.connections.listen_queue.max_size | The maximum allowed size of the listen queue. | long |  | gauge |
| php_fpm.pool.connections.listen_queue.requests.max | The maximum number of requests seen in the listen queue at any one time. | long |  | gauge |
| php_fpm.pool.connections.queued | The number of requests (backlog) currently waiting for a free process. | long |  | gauge |
| php_fpm.pool.name | The name of the FPM process pool. | keyword |  |  |
| php_fpm.pool.process_manager.type | The process manager type - static, dynamic or ondemand. | keyword |  |  |
| php_fpm.pool.processes.active.count | The number of processes that are currently processing requests. | long |  | gauge |
| php_fpm.pool.processes.active.max | The maximum number of concurrently active processes. | long |  | gauge |
| php_fpm.pool.processes.children_reached.max | Has the maximum number of processes ever been reached? If so the displayed value is 1 otherwise the value is 0. | long |  |  |
| php_fpm.pool.processes.count | The current total number of processes. | long |  | gauge |
| php_fpm.pool.processes.idle | The number of processes that are currently idle (waiting for requests). | long |  | gauge |
| php_fpm.pool.slow_requests | The total number of requests that have hit the configured request_slowlog_timeout. | long |  | counter |
| php_fpm.pool.start_since | The time in seconds since the process pool was last started. | long | s | counter |
| php_fpm.pool.start_time | The date/time that the process pool was last started. | long |  | counter |
| tags | List of keywords used to tag each event. | keyword |  |  |

