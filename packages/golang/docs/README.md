# Golang Integration

## Overview

The Golang integration allows you to monitor a [Golang](https://go.dev/) application. Go is a statically typed, compiled programming language designed at Google. It is syntactically similar to C, but with memory safety, garbage collection, structural typing, and CSP-style concurrency. It is often referred to as Golang.

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
- Users can monitor and see the metrics inside the ingested documents for Golang in the `logs-*` index pattern from `Discover`.

## Compatibility

This integration has been tested against Golang versions `1.19` and `1.18`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

### Heap

This is the `heap` data stream. Metrics like heap allocations and GC pause can be collected using `heap` data stream.

An example event for `heap` looks as following:

```json
{
    "@timestamp": "2023-02-01T10:17:48.723Z",
    "agent": {
        "ephemeral_id": "e385e1a9-0d82-4af1-8367-a39f246790b8",
        "id": "ba35afb2-0df7-4d14-8dc2-7a89e4bcbe18",
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
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "ba35afb2-0df7-4d14-8dc2-7a89e4bcbe18",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-02-01T10:17:48.723Z",
        "dataset": "golang.heap",
        "ingested": "2023-02-01T10:17:49Z",
        "kind": "metric",
        "module": "golang",
        "original": "{\"cmdline\":[\"./test\"],\"memstats\":{\"Alloc\":286040,\"BuckHashSys\":3906,\"BySize\":[{\"Frees\":0,\"Mallocs\":0,\"Size\":0},{\"Frees\":46,\"Mallocs\":74,\"Size\":8},{\"Frees\":290,\"Mallocs\":691,\"Size\":16},{\"Frees\":61,\"Mallocs\":82,\"Size\":24},{\"Frees\":41,\"Mallocs\":75,\"Size\":32},{\"Frees\":158,\"Mallocs\":268,\"Size\":48},{\"Frees\":128,\"Mallocs\":157,\"Size\":64},{\"Frees\":15,\"Mallocs\":30,\"Size\":80},{\"Frees\":22,\"Mallocs\":43,\"Size\":96},{\"Frees\":14,\"Mallocs\":18,\"Size\":112},{\"Frees\":47,\"Mallocs\":54,\"Size\":128},{\"Frees\":30,\"Mallocs\":32,\"Size\":144},{\"Frees\":15,\"Mallocs\":31,\"Size\":160},{\"Frees\":0,\"Mallocs\":6,\"Size\":176},{\"Frees\":0,\"Mallocs\":0,\"Size\":192},{\"Frees\":23,\"Mallocs\":44,\"Size\":208},{\"Frees\":13,\"Mallocs\":15,\"Size\":224},{\"Frees\":0,\"Mallocs\":1,\"Size\":240},{\"Frees\":37,\"Mallocs\":52,\"Size\":256},{\"Frees\":3,\"Mallocs\":6,\"Size\":288},{\"Frees\":2,\"Mallocs\":3,\"Size\":320},{\"Frees\":45,\"Mallocs\":52,\"Size\":352},{\"Frees\":0,\"Mallocs\":1,\"Size\":384},{\"Frees\":1,\"Mallocs\":55,\"Size\":416},{\"Frees\":0,\"Mallocs\":0,\"Size\":448},{\"Frees\":0,\"Mallocs\":0,\"Size\":480},{\"Frees\":11,\"Mallocs\":11,\"Size\":512},{\"Frees\":2,\"Mallocs\":4,\"Size\":576},{\"Frees\":1,\"Mallocs\":4,\"Size\":640},{\"Frees\":1,\"Mallocs\":3,\"Size\":704},{\"Frees\":0,\"Mallocs\":0,\"Size\":768},{\"Frees\":1,\"Mallocs\":1,\"Size\":896},{\"Frees\":11,\"Mallocs\":22,\"Size\":1024},{\"Frees\":2,\"Mallocs\":4,\"Size\":1152},{\"Frees\":1,\"Mallocs\":3,\"Size\":1280},{\"Frees\":1,\"Mallocs\":1,\"Size\":1408},{\"Frees\":86,\"Mallocs\":99,\"Size\":1536},{\"Frees\":0,\"Mallocs\":4,\"Size\":1792},{\"Frees\":21,\"Mallocs\":23,\"Size\":2048},{\"Frees\":1,\"Mallocs\":3,\"Size\":2304},{\"Frees\":1,\"Mallocs\":2,\"Size\":2688},{\"Frees\":0,\"Mallocs\":0,\"Size\":3072},{\"Frees\":0,\"Mallocs\":0,\"Size\":3200},{\"Frees\":0,\"Mallocs\":0,\"Size\":3456},{\"Frees\":57,\"Mallocs\":61,\"Size\":4096},{\"Frees\":5,\"Mallocs\":7,\"Size\":4864},{\"Frees\":0,\"Mallocs\":1,\"Size\":5376},{\"Frees\":13,\"Mallocs\":14,\"Size\":6144},{\"Frees\":0,\"Mallocs\":0,\"Size\":6528},{\"Frees\":0,\"Mallocs\":0,\"Size\":6784},{\"Frees\":0,\"Mallocs\":0,\"Size\":6912},{\"Frees\":1,\"Mallocs\":3,\"Size\":8192},{\"Frees\":0,\"Mallocs\":12,\"Size\":9472},{\"Frees\":0,\"Mallocs\":0,\"Size\":9728},{\"Frees\":0,\"Mallocs\":0,\"Size\":10240},{\"Frees\":0,\"Mallocs\":0,\"Size\":10880},{\"Frees\":0,\"Mallocs\":0,\"Size\":12288},{\"Frees\":0,\"Mallocs\":0,\"Size\":13568},{\"Frees\":0,\"Mallocs\":0,\"Size\":14336},{\"Frees\":0,\"Mallocs\":0,\"Size\":16384},{\"Frees\":0,\"Mallocs\":0,\"Size\":18432}],\"DebugGC\":false,\"EnableGC\":true,\"Frees\":1329,\"GCCPUFraction\":0.00008866715026361546,\"GCSys\":8593488,\"HeapAlloc\":286040,\"HeapIdle\":2834432,\"HeapInuse\":868352,\"HeapObjects\":865,\"HeapReleased\":2637824,\"HeapSys\":3702784,\"LastGC\":1675246668664461000,\"Lookups\":0,\"MCacheInuse\":14400,\"MCacheSys\":15600,\"MSpanInuse\":54400,\"MSpanSys\":65280,\"Mallocs\":2194,\"NextGC\":4194304,\"NumForcedGC\":15,\"NumGC\":15,\"OtherSys\":1331342,\"PauseEnd\":[1675246654649875700,1675246655651008500,1675246656651925500,1675246657652856300,1675246658653773300,1675246659655028200,1675246660656272400,1675246661657298000,1675246662658424000,1675246663659243300,1675246664660357400,1675246665661794600,1675246666662344200,1675246667663702800,1675246668664461000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"PauseNs\":[92033,45637,38257,42954,44695,55030,73403,56834,40821,47882,66027,39846,39209,41114,55981,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"PauseTotalNs\":779723,\"StackInuse\":491520,\"StackSys\":491520,\"Sys\":14203920,\"TotalAlloc\":978912}}",
        "type": [
            "info"
        ]
    },
    "golang": {
        "heap": {
            "allocations": {
                "active": {
                    "bytes": 868352
                },
                "frees": {
                    "count": 1329
                },
                "idle": {
                    "bytes": 2834432
                },
                "object": {
                    "bytes": 286040,
                    "count": 865
                },
                "total": {
                    "bytes": 978912
                }
            },
            "cmdline": [
                "./test"
            ],
            "gc": {
                "cpu_fraction": 0.00008866715026361546,
                "next_gc_limit": 4194304,
                "pause": {
                    "total": {
                        "ns": 779723
                    }
                },
                "total": {
                    "count": 15
                }
            },
            "mallocs": {
                "count": 2194
            },
            "system": {
                "released": {
                    "bytes": 2637824
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
    "service": {
        "address": "http://elastic-package-service_golang_1:6060"
    },
    "tags": [
        "preserve_original_event",
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
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |  |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |  |  |
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
| golang.heap.gc.pause.total.ns | The cumulative nanoseconds in GC stop-the-world pauses since the program started. | long | nanos | counter |
| golang.heap.gc.total.count | The number of completed GC cycles. | long |  | counter |
| golang.heap.mallocs.count | Mallocs is the cumulative count of heap objects allocated in this size class. | long |  | gauge |
| golang.heap.system.released.bytes | Bytes of physical memory returned to the OS. | long | byte | gauge |
| golang.heap.system.stack.bytes | Bytes of stack memory obtained from the OS. | long | byte | gauge |
| golang.heap.system.total.bytes | Bytes of heap memory obtained from the OS. | long | byte | gauge |
| input.type | Type of Filebeat input. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
