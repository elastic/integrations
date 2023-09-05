# PHP-FPM Integration

## Overview

PHP-FPM (FastCGI Process Manager) is a web tool used to speed up the performance of a website. It is much faster than traditional CGI based methods and has the ability to handle tremendous loads simultaneously.

## Data streams

The PHP-FPM integration collects metrics data.

Metrics give you insight into the statistics of the PHP-FPM. Metrics data streams collected by the PHP-FPM integration include [pool](https://www.php.net/manual/en/fpm.status.php#:~:text=Basic%20information%20%2D%20Always%20displayed%20on%20the%20status%20page) and [process](https://www.php.net/manual/en/fpm.status.php#:~:text=Per%2Dprocess%20information%20%2D%20only%20displayed%20in%20full%20output%20mode) so that the user can monitor and troubleshoot the performance of the PHP-FPM instances.

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

### Troubleshooting

If host.ip is shown conflicted under ``logs-*`` data view, then this issue can be solved by reindexing the ``Pool`` and ``Process`` data stream's indices.
To reindex the data, the following steps must be performed.

1. Stop the data stream by going to `Integrations -> PHP-FPM -> Integration policies` open the configuration of PHP-FPM and disable the `Collect PHP-FPM metrics` toggle to reindex metrics data stream and save the integration.

2. Copy data into the temporary index and delete the existing data stream and index template by performing the following steps in the Dev tools.

```
POST _reindex
{
  "source": {
    "index": "<index_name>"
  },
  "dest": {
    "index": "temp_index"
  }
}  
```
Example:
```
POST _reindex
{
  "source": {
    "index": "logs-php_fpm.pool-default"
  },
  "dest": {
    "index": "temp_index"
  }
}
```

```
DELETE /_data_stream/<data_stream>
```
Example:
```
DELETE /_data_stream/logs-php_fpm.pool-default
```

```
DELETE _index_template/<index_template>
```
Example:
```
DELETE _index_template/logs-php_fpm.pool
```
3. Go to `Integrations -> PHP-FPM -> Settings` and click on `Reinstall PHP-FPM`.

4. Copy data from temporary index to new index by performing the following steps in the Dev tools.

```
POST _reindex
{
  "conflicts": "proceed",
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "<index_name>",
    "op_type": "create"

  }
}
```
Example:
```
POST _reindex
{
  "conflicts": "proceed",
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "logs-php_fpm.pool-default",
    "op_type": "create"

  }
}
```

5. Verify data is reindexed completely.

6. Start the data stream by going to the `Integrations -> PHP-FPM -> Integration policies` and open configuration of integration and enable the `Collect PHP-FPM metrics` toggle and save the integration.

7. Delete temporary index by performing the following step in the Dev tools.

```
DELETE temp_index
```

More details about reindexing can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).

## Metrics reference

### Pool

This is the `pool` data stream. `pool` data stream collects metrics related to the setup and contents of the FPM status page.

An example event for `pool` looks as following:

```json
{
    "@timestamp": "2023-07-28T10:10:15.918Z",
    "agent": {
        "ephemeral_id": "9581f949-002c-4a1f-8939-abae313a3e55",
        "id": "79efec86-f67c-4ca6-8a2e-a8900f9ae3ac",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
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
        "id": "79efec86-f67c-4ca6-8a2e-a8900f9ae3ac",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web",
            "configuration",
            "process"
        ],
        "created": "2023-07-28T10:10:15.918Z",
        "dataset": "php_fpm.pool",
        "ingested": "2023-07-28T10:10:19Z",
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
            "start_since": 17,
            "start_time": 1690538998
        }
    },
    "service": {
        "address": "http://elastic-package-service_php_fpm_1"
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
| host.ip | Host ip addresses. | ip |  |  |
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
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |


### Process

This is the `process` data stream. `process` data stream collects metrics like request duration, content length, process state, etc.

An example event for `process` looks as following:

```json
{
    "@timestamp": "2023-07-28T10:11:12.080Z",
    "agent": {
        "ephemeral_id": "0f5589f7-327f-468e-b368-00ada3a96721",
        "id": "79efec86-f67c-4ca6-8a2e-a8900f9ae3ac",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
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
        "id": "79efec86-f67c-4ca6-8a2e-a8900f9ae3ac",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web",
            "configuration",
            "process"
        ],
        "created": "2023-07-28T10:11:12.080Z",
        "dataset": "php_fpm.process",
        "ingested": "2023-07-28T10:11:15Z",
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
                "count": 1,
                "duration": 581,
                "last": {
                    "cpu": {
                        "pct": 0
                    },
                    "memory": 0
                }
            },
            "script": "-",
            "start_since": 0,
            "start_time": 1690539072,
            "state": "Running"
        }
    },
    "process": {
        "pid": 33
    },
    "service": {
        "address": "http://elastic-package-service_php_fpm_1"
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
| host.ip | Host ip addresses. | ip |  |  |
| http.request.body.bytes | Size in bytes of the request body. | long |  |  |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |
| php_fpm.process.pool.name | The name of the FPM process pool. | keyword |  |  |
| php_fpm.process.request.count | The total number of requests served. | long |  | counter |
| php_fpm.process.request.duration | The duration in microseconds of the requests. | long | micros | gauge |
| php_fpm.process.request.last.cpu.pct | The %cpu of the last request. This will be 0 if the process is not Idle because the calculation is done when the request processing is complete. | long | percent | gauge |
| php_fpm.process.request.last.memory | The maximum amount of memory consumed by the last request. This will be 0 if the process is not Idle because the calculation is done when the request processing is complete. | long |  | gauge |
| php_fpm.process.script | The full path of the script executed by the last request. This will be '-' if not applicable (eg. status page requests). | keyword |  |  |
| php_fpm.process.start_since | The number of seconds since the process started. | long | s | counter |
| php_fpm.process.start_time | The date/time at which the process started. | long |  |  |
| php_fpm.process.state | The state of the process. | keyword |  |  |
| process.pid | Process id. | long |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |  |  |
| url.original.text | Multi-field of `url.original`. | match_only_text |  |  |
| user.name | Short name or login of the user. | keyword |  |  |
| user.name.text | Multi-field of `user.name`. | match_only_text |  |  |
