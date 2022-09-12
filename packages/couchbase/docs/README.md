# Couchbase Integration

This Elastic integration collects and parses [Bucket](https://docs.couchbase.com/server/current/rest-api/rest-buckets-summary.html) and [Cluster](https://docs.couchbase.com/server/current/rest-api/rest-cluster-details.html) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses `http` metricbeat module to collect `bucket` and `cluster` metrics.

Note: For Couchbase cluster setup, there is an ideal scenario of single host with administrator access for the entire cluster to collect metrics. Providing multiple host from the same cluster might lead to data duplication. In case of multiple clusters, adding a new integration to collect data from different cluster host is a good option.

## Compatibility

This integration has been tested against Couchbase `v6.6`, `v7.0` and `v7.1`.

## Requirements

In order to ingest data from Couchbase, you must know the host(s) and the administrator credentials for the Couchbase instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://Administrator:password@localhost:8091`

## Metrics

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


### Cluster

This is the `cluster` data stream. A cluster is a collection of nodes that are accessed and managed as a single group. Each node is an equal partner in orchestrating the cluster to provide facilities such as operational information (monitoring) or managing cluster membership of nodes and health of nodes.

An example event for `cluster` looks as following:

```json
{
    "@timestamp": "2022-07-28T06:12:30.084Z",
    "agent": {
        "ephemeral_id": "29c9e6b7-8cac-4452-9f3f-b8934052b319",
        "id": "8afbcf13-ea5f-4341-8d24-1b2826ad8010",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.2"
    },
    "couchbase": {
        "cluster": {
            "buckets": {
                "max": {
                    "count": 30
                }
            },
            "hdd": {
                "free": {
                    "bytes": 30303183422
                },
                "quota": {
                    "total": {
                        "bytes": 104493735936
                    }
                },
                "total": {
                    "bytes": 104493735936
                },
                "used": {
                    "data": {
                        "bytes": 22595962
                    },
                    "value": {
                        "bytes": 74190552514
                    }
                }
            },
            "memory": {
                "quota": {
                    "index": {
                        "mb": 300
                    },
                    "mb": 300
                }
            },
            "ram": {
                "quota": {
                    "total": {
                        "per_node": {
                            "bytes": 314572800
                        },
                        "value": {
                            "bytes": 314572800
                        }
                    },
                    "used": {
                        "per_node": {
                            "bytes": 104857600
                        },
                        "value": {
                            "bytes": 104857600
                        }
                    }
                },
                "total": {
                    "bytes": 12527374336
                },
                "used": {
                    "data": {
                        "bytes": 33342376
                    },
                    "value": {
                        "bytes": 10380521472
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.cluster",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "8afbcf13-ea5f-4341-8d24-1b2826ad8010",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.cluster",
        "duration": 7422215,
        "ingested": "2022-07-28T06:12:33Z",
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
            "172.18.0.7"
        ],
        "mac": [
            "02:42:ac:12:00:07"
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
        "address": "http://elastic-package-service_couchbase_1:8091/pools/default",
        "type": "http"
    },
    "tags": [
        "forwarded",
        "couchbase-cluster"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| couchbase.cluster.buckets.max.count | Maximum number of buckets. | long |  |  |
| couchbase.cluster.hdd.free.bytes | Free hard drive space in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.hdd.quota.total.bytes | Hard drive quota total for the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.hdd.total.bytes | Total hard drive space available to the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.hdd.used.data.bytes | Hard drive space used by the data in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.hdd.used.value.bytes | Hard drive space used by the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.memory.quota.index.mb | Memory quota setting for the Index service (Mbyte). | long | byte | gauge |
| couchbase.cluster.memory.quota.mb | Memory quota setting for the cluster (Mbyte). | long | byte | gauge |
| couchbase.cluster.ram.quota.total.per_node.bytes | RAM quota used by the current node in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.quota.total.value.bytes | RAM quota total for the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.quota.used.per_node.bytes | Ram quota used by the current node in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.quota.used.value.bytes | RAM quota used by the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.total.bytes | Total RAM available to cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.used.data.bytes | RAM used by the data in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.used.value.bytes | RAM used by the cluster (bytes). | long | byte | gauge |
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
