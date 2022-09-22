# Couchbase Integration

## Overview

The Couchbase integration allows you to monitor your Couchbase instance. Couchbase Server is an open-source, distributed multi-model NoSQL document-oriented database software package optimized for interactive applications.

Use the Couchbase integration to collect metrics related to the bucket, cluster, and sync gateway. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, you could use the data from this integration to know when there are more than some number of failed authentication requests for a single piece of content in a given time period. You could also use the data to troubleshoot the underlying issue by looking at the documents ingested in Elasticsearch.

## Data streams

The Couchbase integration collects metrics data.

Metrics give you insight into the state of the Couchbase. Metrics data streams collected by the Couchbase integration include [Bucket](https://docs.couchbase.com/server/current/rest-api/rest-buckets-summary.html),  [Cluster](https://docs.couchbase.com/server/current/rest-api/rest-cluster-details.html), [Couchbase Lite Replication](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#cbl_replication_pull), [Delta Sync](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#delta_sync), [GSI views](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#gsi_views), [Import](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#shared_bucket_import), [Resource Utilization](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#resource_utilization), and [Security](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#security) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses:
- `http` metricbeat module to collect `bucket` and `cluster` metrics.
- `prometheus` metricbeat module to collect `cbl_replication`, `delta_sync`, `gsi_views`, `import`, `resource`, and `security` metrics.

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


### Cluster

This is the `cluster` data stream. A cluster is a collection of nodes that are accessed and managed as a single group. Each node is an equal partner in orchestrating the cluster to provide facilities such as operational information (monitoring) or managing cluster membership of nodes and the health of nodes.

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


### Couchbase Lite Replication

This is the `cbl_replication` data stream.

CBL Replication push is a process by which clients upload database changes from the local source database to the remote (server) target database.

CBL Replication pull is a process by which clients download database changes from the remote (server) source database to the local target database.

An example event for `cbl_replication` looks as following:

```json
{
    "@timestamp": "2022-08-01T12:29:02.626Z",
    "agent": {
        "ephemeral_id": "e90e29db-34fd-4bba-a4bf-da0c2e5f1d15",
        "id": "980dcead-2dc9-4d20-a59b-a81f43d3a52c",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.2"
    },
    "couchbase": {
        "cbl_replication": {
            "database": {
                "name": "beer-sample"
            },
            "pull": {
                "attachment": {
                    "bytes": 0,
                    "count": 0
                },
                "num": {
                    "caught_up": 0,
                    "continuous": {
                        "active": 0,
                        "total": 0
                    },
                    "one_shot": {
                        "active": 0,
                        "total": 0
                    },
                    "since_zero": 0
                },
                "request": {
                    "changes": {
                        "time": 0
                    }
                },
                "rev": {
                    "latency": {
                        "send": 0
                    }
                }
            },
            "push": {
                "attachment": {
                    "bytes": 0,
                    "count": 0
                },
                "conflict": {
                    "write": {
                        "count": 0
                    }
                },
                "doc": {
                    "count": 0
                },
                "propose": {
                    "change": {
                        "count": 0,
                        "time": 0
                    }
                },
                "sync": {
                    "function": {
                        "time": 1732351964
                    }
                },
                "write": {
                    "processing": {
                        "time": 0
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.cbl_replication",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "980dcead-2dc9-4d20-a59b-a81f43d3a52c",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.cbl_replication",
        "duration": 50168237,
        "ingested": "2022-08-01T12:29:03Z",
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
            "192.168.192.6"
        ],
        "mac": [
            "02:42:c0:a8:c0:06"
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
        "couchbase-cbl_replication",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| couchbase.cbl_replication.database.name | The database for which the data is being extracted. | keyword |  |  |
| couchbase.cbl_replication.pull.attachment.bytes | The total size of attachments pulled. This is the pre-compressed size. | long | byte | counter |
| couchbase.cbl_replication.pull.attachment.count | The total number of attachments pulled. | long |  | counter |
| couchbase.cbl_replication.pull.num.caught_up | The total number of replications which have caught up to the latest changes. | long |  | gauge |
| couchbase.cbl_replication.pull.num.continuous.active | The total number of continuous pull replications in the active state. | long |  | gauge |
| couchbase.cbl_replication.pull.num.continuous.total | The total number of continuous pull replications. | long |  | gauge |
| couchbase.cbl_replication.pull.num.one_shot.active | The total number of one-shot pull replications in the active state. | long |  | gauge |
| couchbase.cbl_replication.pull.num.one_shot.total | The total number of one-shot pull replications. | long |  | gauge |
| couchbase.cbl_replication.pull.num.since_zero | The total number of new replications started (/_changes?since=0). | long |  | counter |
| couchbase.cbl_replication.pull.request.changes.time | The total time taken to perform the requested changes. | scaled_float | s | counter |
| couchbase.cbl_replication.pull.rev.latency.send | The total amount of time between Sync Gateway receiving a request for a revision and that revision being sent. | scaled_float |  | counter |
| couchbase.cbl_replication.push.attachment.bytes | The total number of attachment bytes pushed. | long | byte | counter |
| couchbase.cbl_replication.push.attachment.count | The total number of attachments pushed. | long |  | counter |
| couchbase.cbl_replication.push.conflict.write.count | The total number of writes that left the document in a conflicted state. Includes new conflicts, and mutations that don’t resolve existing conflicts. | long |  | counter |
| couchbase.cbl_replication.push.doc.count | The total number of documents pushed. | long |  | gauge |
| couchbase.cbl_replication.push.propose.change.count | The total number of changes and-or proposeChanges messages processed since node start-up. | long |  | counter |
| couchbase.cbl_replication.push.propose.change.time | The total time spent processing changes and/or proposeChanges messages. | scaled_float | s | counter |
| couchbase.cbl_replication.push.sync.function.time | The total time spent evaluating the sync_function. | scaled_float | s | counter |
| couchbase.cbl_replication.push.write.processing.time | Total time spent processing writes. Measures complete request-to-response time for a write. | scaled_float | s | gauge |
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
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |


### Delta Sync, Import, Security and GSI views

This is the `miscellaneous` data stream.

The Delta Sync provides the ability to replicate only those parts of a Couchbase Mobile document that have changed.

The import is processed with an admin user context in the Sync Function, similar to writes made through the Sync Gateway Admin API.

The Security metrics give the metrics related to authentication requests such as number of authentication failures and number of access errors.

Global Secondary Indexes (GSI) support queries made by the Query Service.

An example event for `miscellaneous` looks as following:

```json
{
    "@timestamp": "2022-09-07T12:09:30.395Z",
    "agent": {
        "ephemeral_id": "b53d49b9-ac2c-4c23-956a-61b60d17ed45",
        "id": "52f5e6b6-f0bd-445c-b9fc-35a9e47ae49b",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.3"
    },
    "couchbase": {
        "miscellaneous": {
            "database": {
                "name": "beer-sample"
            },
            "delta_sync": {
                "cache": {
                    "hits": 0
                },
                "pull": {
                    "replications": 0
                },
                "push": {
                    "documents": 0
                },
                "requested": 0,
                "sent": 0
            },
            "gsi_views": {
                "access": {
                    "count": 0
                },
                "all_docs": {
                    "count": 0
                },
                "channels": {
                    "count": 0
                },
                "role_access": {
                    "count": 0
                }
            },
            "security": {
                "access": {
                    "errors": {
                        "count": 0
                    }
                },
                "authentications": {
                    "failed": {
                        "count": 0
                    }
                },
                "documents": {
                    "rejected": {
                        "count": 0
                    }
                }
            },
            "shared_bucket": {
                "import": {
                    "documents": {
                        "count": 31486,
                        "errors": {
                            "count": 105
                        }
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.miscellaneous",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "52f5e6b6-f0bd-445c-b9fc-35a9e47ae49b",
        "snapshot": false,
        "version": "8.3.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.miscellaneous",
        "duration": 298010717,
        "ingested": "2022-09-07T12:09:31Z",
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
            "172.23.0.7"
        ],
        "mac": [
            "02:42:ac:17:00:07"
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
        "couchbase-miscellaneous",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| couchbase.miscellaneous.database.name | The database for which the data is being extracted. | keyword |  |
| couchbase.miscellaneous.delta_sync.cache.hits | The total number of requested deltas that were available in the revision cache. | long | counter |
| couchbase.miscellaneous.delta_sync.pull.replications | The number of delta replications that have been run. | long | counter |
| couchbase.miscellaneous.delta_sync.push.documents | The total number of documents pushed as a delta from a previous revision. | long | counter |
| couchbase.miscellaneous.delta_sync.requested | The total number of times a revision is sent as delta from a previous revision. | long | counter |
| couchbase.miscellaneous.delta_sync.sent | The total number of revisions sent to clients as deltas. | long | counter |
| couchbase.miscellaneous.gsi_views.access.count | The total number of 'access' queries performed. | long | counter |
| couchbase.miscellaneous.gsi_views.all_docs.count | The total number of 'allDocs' queries performed. | long | counter |
| couchbase.miscellaneous.gsi_views.channels.count | The total number of 'channels' queries performed. | long | counter |
| couchbase.miscellaneous.gsi_views.role_access.count | The total number of 'roleAccess' queries performed. | long | counter |
| couchbase.miscellaneous.security.access.errors.count | The total number of documents rejected by write access functions (requireAccess, requireRole, requireUser). | long | counter |
| couchbase.miscellaneous.security.authentications.failed.count | The total number of unsuccessful authentications. | long | counter |
| couchbase.miscellaneous.security.documents.rejected.count | The total number of documents rejected by the sync_function. | long | counter |
| couchbase.miscellaneous.shared_bucket.import.documents.count | The total number of documents imported. | long | counter |
| couchbase.miscellaneous.shared_bucket.import.documents.errors.count | The total number of errors arising as a result of a document import. | long | counter |
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


### Resource Utilization

This is the `resource` data stream. The Resource Utilization metrics are related to [MemStats](https://golang.org/pkg/runtime/#MemStats) records statistics about the memory allocator.

An example event for `resource` looks as following:

```json
{
    "@timestamp": "2022-08-01T16:19:43.614Z",
    "agent": {
        "ephemeral_id": "fd354a8c-e906-40b4-9828-a806f6e5a747",
        "id": "8c9fc977-b861-4bc8-81a2-68143b5b85ba",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.2"
    },
    "couchbase": {
        "resource": {
            "admin_net": {
                "bytes": {
                    "received": 0,
                    "sent": 0
                }
            },
            "error": {
                "count": 0
            },
            "go_memstats": {
                "heap": {
                    "alloc": 0,
                    "idle": 0,
                    "in_use": 0,
                    "released": 0
                },
                "stack": {
                    "in_use": 0
                }
            },
            "last_gc": 1.66,
            "process": {
                "cpu": {
                    "pct": 0
                },
                "memory": {
                    "resident": 0
                }
            },
            "warn": {
                "count": 14
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.resource",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "8c9fc977-b861-4bc8-81a2-68143b5b85ba",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.resource",
        "duration": 24160284,
        "ingested": "2022-08-01T16:19:47Z",
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
            "172.31.0.6"
        ],
        "mac": [
            "02:42:ac:1f:00:06"
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
        "couchbase-resource",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| couchbase.resource.admin_net.bytes.received | The total number of bytes received (since node start-up) on the network interface to which the Sync Gateway api.admin_interface is bound. | scaled_float | byte | gauge |
| couchbase.resource.admin_net.bytes.sent | The total number of bytes sent (since node start-up) on the network interface to which the Sync Gateway api.admin_interface is bound. | scaled_float | byte | gauge |
| couchbase.resource.error.count | The total number of errors logged. | long |  | counter |
| couchbase.resource.go_memstats.heap.alloc | Bytes of allocated heap objects. | scaled_float | byte | gauge |
| couchbase.resource.go_memstats.heap.idle | Bytes in idle (unused) spans. | scaled_float | byte | gauge |
| couchbase.resource.go_memstats.heap.in_use | Bytes in in-use spans. | scaled_float | byte | gauge |
| couchbase.resource.go_memstats.heap.released | Bytes of physical memory returned to the OS. | scaled_float | byte | gauge |
| couchbase.resource.go_memstats.stack.in_use | Bytes in stack spans. | scaled_float | byte | gauge |
| couchbase.resource.last_gc | The time the last garbage collection finished, as nanoseconds since 1970 (the UNIX epoch). | scaled_float | nanos | gauge |
| couchbase.resource.process.cpu.pct | The CPU’s utilization as percentage value. | scaled_float | percent | gauge |
| couchbase.resource.process.memory.resident | The memory utilization (Resident Set Size) for the process, in bytes. | scaled_float | byte | gauge |
| couchbase.resource.warn.count | The total number of warnings logged. | long |  | counter |
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
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |

