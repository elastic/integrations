# Couchbase Integration

This Elastic integration collects and parses the [Node](https://docs.couchbase.com/server/current/rest-api/rest-cluster-details.html) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses `couchbase` metricbeat module to collect `node` metrics.

## Compatibility

This integration has been tested against Couchbase `v6.6`, `v7.0` and `v7.1`.

## Requirements

In order to ingest data from Couchbase, you must know the host(s) and the administrator credentials for the Couchbase instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://Administrator:password@localhost:8091`

## Metrics

### Node

This is the `node` data stream.

An example event for `node` looks as following:

```json
{
    "@timestamp": "2022-07-05T07:36:06.269Z",
    "agent": {
        "ephemeral_id": "d447a1e7-b866-4a98-88b2-aae7a84769aa",
        "id": "33f71fd5-342c-4824-bc61-8740261bb1ff",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "couchbase": {
        "node": {
            "commands": {
                "get": {
                    "count": 0
                }
            },
            "couch": {
                "docs": {
                    "data_size": {
                        "bytes": 18914304
                    },
                    "disk_size": {
                        "bytes": 18932289
                    }
                },
                "spatial": {
                    "data_size": {
                        "bytes": 0
                    },
                    "disk_size": {
                        "bytes": 0
                    }
                },
                "views": {
                    "data_size": {
                        "bytes": 769578
                    },
                    "disk_size": {
                        "bytes": 773730
                    }
                }
            },
            "cpu_utilization_rate": {
                "pct": 10.40100250626566
            },
            "current_items": {
                "total": 7303,
                "value": 7303
            },
            "ep_bg_fetched": 0,
            "get": {
                "hits": 0
            },
            "hostname": "192.168.176.4:8091",
            "memcached": {
                "allocated": {
                    "bytes": 9557
                },
                "reserved": {
                    "bytes": 9557
                }
            },
            "memory": {
                "free": {
                    "bytes": 7165845504
                },
                "total": {
                    "bytes": 12527374336
                },
                "used": {
                    "bytes": 35921000
                }
            },
            "operations": {
                "count": 0
            },
            "swap": {
                "total": {
                    "bytes": 4126142464
                },
                "used": {
                    "bytes": 0
                }
            },
            "uptime": {
                "sec": 63
            },
            "vb_replica": {
                "items": {
                    "current": 0
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.node",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "33f71fd5-342c-4824-bc61-8740261bb1ff",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.node",
        "duration": 5471277,
        "ingested": "2022-07-05T07:36:09Z",
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
            "192.168.176.7"
        ],
        "mac": [
            "02:42:c0:a8:b0:07"
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
        "name": "node",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_couchbase_1:8091/pools/default",
        "type": "couchbase"
    },
    "tags": [
        "forwarded",
        "couchbase-node"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| couchbase.node.commands.get.count | Number of get commands. | long |  |  |
| couchbase.node.couch.docs.data_size.bytes | Data size of Couch docs associated with a node (bytes). | long | byte | gauge |
| couchbase.node.couch.docs.disk_size.bytes | Amount of disk space used by Couch docs (bytes). | long | byte | gauge |
| couchbase.node.couch.spatial.data_size.bytes | Size of object data for spatial views (bytes). | long | byte | gauge |
| couchbase.node.couch.spatial.disk_size.bytes | Amount of disk space used by spatial views (bytes). | long | byte | gauge |
| couchbase.node.couch.views.data_size.bytes | Size of object data for Couch views (bytes). | long | byte | gauge |
| couchbase.node.couch.views.disk_size.bytes | Amount of disk space used by Couch views (bytes). | long | byte | gauge |
| couchbase.node.cpu_utilization_rate.pct | The CPU utilization rate (%). | float | percent | gauge |
| couchbase.node.current_items.total | Total number of items associated with the node. | long |  |  |
| couchbase.node.current_items.value | Number of current items. | long |  |  |
| couchbase.node.ep_bg_fetched | Number of disk fetches performed since the server was started. | long |  |  |
| couchbase.node.get.hits | Number of hits get. | long |  |  |
| couchbase.node.hostname | The hostname of the node. | keyword |  |  |
| couchbase.node.memcached.allocated.bytes | Amount of memcached memory allocated (bytes). | long | byte | gauge |
| couchbase.node.memcached.reserved.bytes | Amount of memcached memory reserved (bytes). | long | byte | gauge |
| couchbase.node.memory.free.bytes | Amount of memory free for the node (bytes). | long | byte | gauge |
| couchbase.node.memory.total.bytes | Total memory available to the node (bytes). | long | byte | gauge |
| couchbase.node.memory.used.bytes | Memory used by the node (bytes). | long | byte | gauge |
| couchbase.node.operations.count | Number of operations performed on Couchbase. | long |  |  |
| couchbase.node.swap.total.bytes | Total swap size allocated (bytes). | long | byte | gauge |
| couchbase.node.swap.used.bytes | Amount of swap space used (bytes). | long | byte | gauge |
| couchbase.node.uptime.sec | Time during which the node was in operation (sec). | long | s |  |
| couchbase.node.vb_replica.items.current | Number of items/documents that are replicas. | long |  |  |
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
