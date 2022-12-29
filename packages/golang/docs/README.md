# Golang Integration

## Overview

The Golang integration allows you to monitor a [Golang](https://go.dev/) application. Go is a statically typed, compiled programming language designed at Google. It is syntactically similar to C, but with memory safety, garbage collection, structural typing, and CSP-style concurrency. It is often referred to as Golang because of its former domain name, golang.org, but its proper name is Go.

Use the Golang integration to:
- Gain insights into heap statistics.
- Create visualizations to monitor, measure and analyze the state of heap.
## Data streams

The Golang integration collects metrics using [expvar](https://pkg.go.dev/expvar) package. Metrics are exported on "/debug/vars" endpoint after [importing](https://pkg.go.dev/expvar#:~:text=into%20your%20program%3A-,import%20_%20%22expvar%22,-Index%20%C2%B6) expvar package and adding an HTTP handler.

**Logs** help you keep a record of state of Golang application.
Log data streams collected by the Golang integration include [Heap](https://go.dev/src/runtime/mstats.go#:~:text=118%20119%20%2F%2F%20HeapAlloc%20is%20bytes%20of%20allocated%20heap%20objects.).

Data streams:
- `heap`:  Collects heap metrics like heap allocation and garbage collection metrics.

Note: 
- Users can monitor and see the metrics inside the ingested documents for Golang in the logs-* index pattern from `Discover`.

## Compatibility

This integration has been tested against Golang versions `1.19` and `1.18`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.
## Set Up

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

### Heap

This is the `heap` data stream. Metrics like heap allocations and GC pause can be collected using `heap` data stream.

Note: 
- Field with name "last_num_gc" is added in the raw response which can be seen in event.original field if the Preserve original event toggle is enabled, this field is used to process metrics related to GC pause and does not occur in actual response.

An example event for `heap` looks as following:

```json
{
    "@timestamp": "2022-12-29T13:33:18.888Z",
    "agent": {
        "ephemeral_id": "ff243107-9982-422d-bd97-c58c8fc7d53d",
        "id": "8a0d287b-3191-4ef5-a995-51d996222f07",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "data_stream": {
        "dataset": "golang.heap",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "8a0d287b-3191-4ef5-a995-51d996222f07",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-12-29T13:33:18.888Z",
        "dataset": "golang.heap",
        "ingested": "2022-12-29T13:33:19Z",
        "kind": "metric",
        "module": "golang",
        "type": [
            "info"
        ]
    },
    "golang": {
        "heap": {
            "allocations": {
                "active": {
                    "bytes": 933888
                },
                "frees": {
                    "count": 1399
                },
                "idle": {
                    "bytes": 2768896
                },
                "object": {
                    "bytes": 336504,
                    "count": 948
                },
                "total": {
                    "bytes": 1032736
                }
            },
            "cmdline": [
                "./test"
            ],
            "gc": {
                "cpu_fraction": 0.00013856427071891136,
                "next_gc_limit": 4194304,
                "pause": {
                    "avg": {
                        "ns": 96820
                    },
                    "count": 21,
                    "max": {
                        "ns": 251674
                    },
                    "sum": {
                        "ns": 2033225
                    },
                    "total": {
                        "ns": 2033225
                    }
                },
                "total": {
                    "count": 21
                }
            },
            "mallocs": {
                "count": 2347
            },
            "system": {
                "released": {
                    "bytes": 2695168
                },
                "stack": {
                    "bytes": 491520
                },
                "total": {
                    "bytes": 3702784
                }
            }
        }
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "forwarded",
        "golang-heap"
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| golang.heap.allocations.active.bytes | Bytes in in-use spans. | long | byte | gauge |
| golang.heap.allocations.frees.count | The cumulative count of heap objects freed. | long |  | gauge |
| golang.heap.allocations.idle.bytes | Bytes in idle (unused) spans. | long | byte | gauge |
| golang.heap.allocations.object.bytes | Bytes of allocated heap objects. | long | byte | gauge |
| golang.heap.allocations.object.count | The number of allocated heap objects. | long |  | gauge |
| golang.heap.allocations.total.bytes | The cumulative bytes allocated for heap objects. | long | byte | counter |
| golang.heap.cmdline | The cmdline of this Go program start with. | keyword |  |  |
| golang.heap.gc.cpu_fraction | The fraction of this program's available CPU time used by the GC since the program started. | float |  | gauge |
| golang.heap.gc.next_gc_limit | The target heap size of the next GC cycle. | long |  | gauge |
| golang.heap.gc.pause.avg.ns | Average GC pause duration during this collect period. | float | nanos | gauge |
| golang.heap.gc.pause.count | Count of GC pause duration during this collect period. | long |  | gauge |
| golang.heap.gc.pause.max.ns | Max GC pause duration during this collect period. | long | nanos | gauge |
| golang.heap.gc.pause.sum.ns | Total GC pause duration during this collect period. | long | nanos | gauge |
| golang.heap.gc.pause.total.ns | The cumulative nanoseconds in GC stop-the-world pauses since the program started. | long | nanos | counter |
| golang.heap.gc.total.count | The number of completed GC cycles. | long |  | counter |
| golang.heap.mallocs.count | Mallocs is the cumulative count of heap objects allocated in this size class. | long |  | gauge |
| golang.heap.system.released.bytes | Bytes of physical memory returned to the OS. | long | byte | gauge |
| golang.heap.system.stack.bytes | Bytes of stack memory obtained from the OS. | long | byte | gauge |
| golang.heap.system.total.bytes | Bytes of heap memory obtained from the OS. | long | byte | gauge |
| input.type | Type of Filebeat input. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
