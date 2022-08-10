# Couchbase Integration

## Overview

The Couchbase integration allows you to monitor your Couchbase instance. Couchbase Server is an open-source, distributed multi-model NoSQL document-oriented database software package optimized for interactive applications.

Use the Couchbase integration to collect metrics related to the bucket, cluster, node, and sync gateway. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, you could use the data from this integration to know when there are more than some number of failed authentication requests for a single piece of content in a given time period. You could also use the data to troubleshoot the underlying issue by looking at the documents ingested in Elasticsearch.

## Data streams

The Couchbase integration collects metrics data.

Metrics give you insight into the state of the Couchbase. Metrics data streams collected by the Couchbase integration include [Bucket](https://docs.couchbase.com/server/current/rest-api/rest-buckets-summary.html), and [Cache](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#cache) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses:
- `http` metricbeat module to collect `bucket` metrics.
- `prometheus` metricbeat module to collect `cache` metrics.

Note: For Couchbase cluster setup, there is an ideal scenario of a single host with administrator access for the entire cluster to collect metrics. Providing multiple hosts from the same cluster might lead to data duplication. In the case of multiple clusters, adding a new integration to collect data from different cluster hosts is a good option.

## Compatibility

This integration has been tested against Couchbase `v6.6`, `v7.0`, and `v7.1`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Couchbase, you must know the host(s) and the administrator credentials for the Couchbase instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://Administrator:password@localhost:8091`

## Setup

In order to collect data using [Sync Gateway](https://www.couchbase.com/products/sync-gateway), follow the steps given below:
- Download and configure [Sync Gateway](https://docs.couchbase.com/sync-gateway/current/get-started-install.html)
- Download and configure [Sync Gateway Promethus Exporter](https://github.com/couchbaselabs/couchbase-sync-gateway-exporter.git) and provide Sync Gateway Host using --sgw.url flag while running the Exporter App
- Example configuration: `--sgw.url=http://sgw:4985`

## Metrics reference

### Bucket

This is the `bucket` data stream. A bucket is a logical container for a related set of items such as key-value pairs or documents.

An example event for `bucket` looks as following:

```json
{
    "@timestamp": "2022-07-22T10:40:36.032Z",
    "agent": {
        "ephemeral_id": "b6b8e21b-ded1-41d8-a193-c5aead533ff1",
        "id": "5d67808a-0fe5-4f5f-9636-ec161f0cdcf0",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.2"
    },
    "couchbase": {
        "bucket": {
            "data": {
                "used": {
                    "bytes": 20892210
                }
            },
            "disk": {
                "fetches": 0,
                "used": {
                    "bytes": 20914347
                }
            },
            "item": {
                "count": 7303
            },
            "memory": {
                "used": {
                    "bytes": 34972008
                }
            },
            "name": "beer-sample",
            "operations_per_sec": 0,
            "ram": {
                "quota": {
                    "bytes": 104857600,
                    "used": {
                        "pct": 33.35190582275391
                    }
                }
            },
            "type": "membase"
        }
    },
    "data_stream": {
        "dataset": "couchbase.bucket",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "5d67808a-0fe5-4f5f-9636-ec161f0cdcf0",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.bucket",
        "duration": 6674276,
        "ingested": "2022-07-22T10:40:39Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.26.0.7"
        ],
        "mac": [
            "02:42:ac:1a:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-110-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_couchbase_1:8091/pools/default/buckets",
        "type": "http"
    },
    "tags": [
        "forwarded",
        "couchbase-bucket"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| couchbase.bucket.data.used.bytes | Size of user data within buckets of the specified state that are resident in RAM. | long | byte | gauge |
| couchbase.bucket.disk.fetches | Number of disk fetches. | long |  | gauge |
| couchbase.bucket.disk.used.bytes | Amount of disk used (bytes). | long | byte | gauge |
| couchbase.bucket.item.count | Number of items associated with the bucket. | long |  | counter |
| couchbase.bucket.memory.used.bytes | Amount of memory used by the bucket (bytes). | long | byte | gauge |
| couchbase.bucket.name | Name of the bucket. | keyword |  |  |
| couchbase.bucket.operations_per_sec | Number of operations per second. | long |  | gauge |
| couchbase.bucket.ram.quota.bytes | Amount of RAM used by the bucket (bytes). | long | byte | gauge |
| couchbase.bucket.ram.quota.used.pct | Percentage of RAM used (for active objects) against the configured bucket size (%). | scaled_float | percent | gauge |
| couchbase.bucket.type | Type of the bucket. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |


### Cache

This is the `cache` data stream. The cache is hardware or software that is used to store something, usually data, temporarily in a computing environment. These metrics are related to caching in Couchbase.

An example event for `cache` looks as following:

```json
{
    "@timestamp": "2022-08-08T10:30:29.005Z",
    "agent": {
        "ephemeral_id": "e3b98a9f-eb9a-47e9-9440-8998d6555a14",
        "id": "dff9a8b1-f1a9-4fab-a250-f953210bd0eb",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.2"
    },
    "couchbase": {
        "cache": {
            "channel": {
                "count": 0,
                "entries": {
                    "max": 0
                },
                "hits": 0,
                "misses": 0,
                "revisions": {
                    "active": 0,
                    "removal": 0,
                    "tombstone": 0
                }
            },
            "database": {
                "name": "travel-sample"
            },
            "revision": {
                "hits": 0,
                "misses": 0
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.cache",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "dff9a8b1-f1a9-4fab-a250-f953210bd0eb",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.cache",
        "duration": 41183313,
        "ingested": "2022-08-08T10:30:32Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.26.0.7"
        ],
        "mac": [
            "02:42:ac:1a:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-110-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "server": {
        "address": "elastic-package-service_exporter_1:9421"
    },
    "service": {
        "address": "http://elastic-package-service_exporter_1:9421/metrics",
        "type": "prometheus"
    },
    "tags": [
        "forwarded",
        "couchbase-cache",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| couchbase.cache.channel.count | The total number of channels being cached. | long | gauge |
| couchbase.cache.channel.entries.max | The total size of the largest channel cache. | long | gauge |
| couchbase.cache.channel.hits | The total number of channel cache requests fully served by the cache. | long | counter |
| couchbase.cache.channel.misses | The total number of channel cache requests not fully served by the cache. | long | counter |
| couchbase.cache.channel.revisions.active | The total number of active revisions in the channel cache. | long | gauge |
| couchbase.cache.channel.revisions.removal | The total number of removal revisions in the channel cache. | long | gauge |
| couchbase.cache.channel.revisions.tombstone | The total number of tombstone revisions in the channel cache. | long | gauge |
| couchbase.cache.database.name | The database for which the data is being extracted. | keyword |  |
| couchbase.cache.revision.hits | The total number of revision cache hits. | long | counter |
| couchbase.cache.revision.misses | The total number of revision cache misses. | long | counter |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |

