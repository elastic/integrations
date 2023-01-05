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

Note: 
- Field with name "last_num_gc" is added in the raw response which can be seen in event.original field if the `Preserve original event` toggle is enabled, this field is used to process metrics related to GC pause and does not occur in actual response.
- Fields `golang.heap.gc.pause.avg.ns`, `golang.heap.gc.pause.count`, `golang.heap.gc.pause.max.ns` and `golang.heap.gc.pause.sum.ns` are derived from `PauseNs` metric which is an array of size 256. After exceeding array size values are [overwritten](https://go.dev/src/runtime/mstats.go#:~:text=PauseNs%20is%20a,during%20a%20cycle.) from the start. In a case where the collection period is very long there is a chance that the array is overwritten multiple times. In this case, some GC cycles can be missed.
- Fields `golang.heap.gc.pause.avg.ns`, `golang.heap.gc.pause.count`, `golang.heap.gc.pause.max.ns` and `golang.heap.gc.pause.sum.ns` are calculated from second last document if filebeat ever restarts.

An example event for `heap` looks as following:

```json
{
    "@timestamp": "2023-01-04T09:56:55.199Z",
    "agent": {
        "ephemeral_id": "7097c4dd-ce9f-4ecd-80d5-7ead7a9c0f52",
        "id": "f8df7dbb-0885-48f4-94f5-f41220174c57",
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
        "id": "f8df7dbb-0885-48f4-94f5-f41220174c57",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-01-04T09:56:55.199Z",
        "dataset": "golang.heap",
        "ingested": "2023-01-04T09:56:56Z",
        "kind": "metric",
        "module": "golang",
        "original": "{\"cmdline\":[\"./test\"],\"last_num_gc\":0,\"memstats\":{\"Alloc\":329760,\"BuckHashSys\":3906,\"BySize\":[{\"Frees\":0,\"Mallocs\":0,\"Size\":0},{\"Frees\":50,\"Mallocs\":78,\"Size\":8},{\"Frees\":304,\"Mallocs\":722,\"Size\":16},{\"Frees\":63,\"Mallocs\":87,\"Size\":24},{\"Frees\":42,\"Mallocs\":78,\"Size\":32},{\"Frees\":168,\"Mallocs\":289,\"Size\":48},{\"Frees\":136,\"Mallocs\":171,\"Size\":64},{\"Frees\":16,\"Mallocs\":32,\"Size\":80},{\"Frees\":24,\"Mallocs\":44,\"Size\":96},{\"Frees\":15,\"Mallocs\":20,\"Size\":112},{\"Frees\":49,\"Mallocs\":59,\"Size\":128},{\"Frees\":32,\"Mallocs\":36,\"Size\":144},{\"Frees\":16,\"Mallocs\":34,\"Size\":160},{\"Frees\":0,\"Mallocs\":6,\"Size\":176},{\"Frees\":0,\"Mallocs\":0,\"Size\":192},{\"Frees\":25,\"Mallocs\":48,\"Size\":208},{\"Frees\":14,\"Mallocs\":17,\"Size\":224},{\"Frees\":0,\"Mallocs\":1,\"Size\":240},{\"Frees\":39,\"Mallocs\":57,\"Size\":256},{\"Frees\":5,\"Mallocs\":9,\"Size\":288},{\"Frees\":2,\"Mallocs\":3,\"Size\":320},{\"Frees\":46,\"Mallocs\":56,\"Size\":352},{\"Frees\":0,\"Mallocs\":1,\"Size\":384},{\"Frees\":1,\"Mallocs\":56,\"Size\":416},{\"Frees\":0,\"Mallocs\":0,\"Size\":448},{\"Frees\":0,\"Mallocs\":0,\"Size\":480},{\"Frees\":11,\"Mallocs\":12,\"Size\":512},{\"Frees\":2,\"Mallocs\":4,\"Size\":576},{\"Frees\":1,\"Mallocs\":4,\"Size\":640},{\"Frees\":1,\"Mallocs\":3,\"Size\":704},{\"Frees\":0,\"Mallocs\":0,\"Size\":768},{\"Frees\":1,\"Mallocs\":1,\"Size\":896},{\"Frees\":11,\"Mallocs\":23,\"Size\":1024},{\"Frees\":2,\"Mallocs\":4,\"Size\":1152},{\"Frees\":1,\"Mallocs\":3,\"Size\":1280},{\"Frees\":1,\"Mallocs\":1,\"Size\":1408},{\"Frees\":94,\"Mallocs\":108,\"Size\":1536},{\"Frees\":0,\"Mallocs\":4,\"Size\":1792},{\"Frees\":21,\"Mallocs\":24,\"Size\":2048},{\"Frees\":1,\"Mallocs\":3,\"Size\":2304},{\"Frees\":1,\"Mallocs\":2,\"Size\":2688},{\"Frees\":0,\"Mallocs\":0,\"Size\":3072},{\"Frees\":0,\"Mallocs\":0,\"Size\":3200},{\"Frees\":0,\"Mallocs\":0,\"Size\":3456},{\"Frees\":60,\"Mallocs\":65,\"Size\":4096},{\"Frees\":5,\"Mallocs\":10,\"Size\":4864},{\"Frees\":0,\"Mallocs\":1,\"Size\":5376},{\"Frees\":14,\"Mallocs\":16,\"Size\":6144},{\"Frees\":0,\"Mallocs\":0,\"Size\":6528},{\"Frees\":0,\"Mallocs\":0,\"Size\":6784},{\"Frees\":0,\"Mallocs\":0,\"Size\":6912},{\"Frees\":1,\"Mallocs\":4,\"Size\":8192},{\"Frees\":0,\"Mallocs\":12,\"Size\":9472},{\"Frees\":0,\"Mallocs\":0,\"Size\":9728},{\"Frees\":0,\"Mallocs\":0,\"Size\":10240},{\"Frees\":0,\"Mallocs\":0,\"Size\":10880},{\"Frees\":0,\"Mallocs\":0,\"Size\":12288},{\"Frees\":0,\"Mallocs\":0,\"Size\":13568},{\"Frees\":0,\"Mallocs\":0,\"Size\":14336},{\"Frees\":0,\"Mallocs\":0,\"Size\":16384},{\"Frees\":0,\"Mallocs\":0,\"Size\":18432}],\"DebugGC\":false,\"EnableGC\":true,\"Frees\":1403,\"GCCPUFraction\":0.00010073414579535309,\"GCSys\":8536168,\"HeapAlloc\":329760,\"HeapIdle\":2744320,\"HeapInuse\":925696,\"HeapObjects\":933,\"HeapReleased\":2449408,\"HeapSys\":3670016,\"LastGC\":1672826214704920800,\"Lookups\":0,\"MCacheInuse\":14400,\"MCacheSys\":15600,\"MSpanInuse\":54400,\"MSpanSys\":65280,\"Mallocs\":2336,\"NextGC\":4194304,\"NumForcedGC\":17,\"NumGC\":17,\"OtherSys\":1060982,\"PauseEnd\":[1672826198687695400,1672826199688851200,1672826200689954800,1672826201691521000,1672826202692936400,1672826203694357200,1672826204695328500,1672826205696802600,1672826206697565000,1672826207699022000,1672826208699799000,1672826209700297500,1672826210701564400,1672826211702674200,1672826212703371300,1672826213704023000,1672826214704920800,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"PauseNs\":[27127,24781,48689,61548,49792,62212,93703,50365,62477,110483,46761,55479,47107,72659,94137,80289,49779,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"PauseTotalNs\":1037388,\"StackInuse\":524288,\"StackSys\":524288,\"Sys\":13876240,\"TotalAlloc\":1057848}}",
        "type": [
            "info"
        ]
    },
    "golang": {
        "heap": {
            "allocations": {
                "active": {
                    "bytes": 925696
                },
                "frees": {
                    "count": 1403
                },
                "idle": {
                    "bytes": 2744320
                },
                "object": {
                    "bytes": 329760,
                    "count": 933
                },
                "total": {
                    "bytes": 1057848
                }
            },
            "cmdline": [
                "./test"
            ],
            "gc": {
                "cpu_fraction": 0.00010073414579535309,
                "next_gc_limit": 4194304,
                "pause": {
                    "avg": {
                        "ns": 61022.824
                    },
                    "count": 17,
                    "max": {
                        "ns": 110483
                    },
                    "sum": {
                        "ns": 1037388
                    },
                    "total": {
                        "ns": 1037388
                    }
                },
                "total": {
                    "count": 17
                }
            },
            "mallocs": {
                "count": 2336
            },
            "system": {
                "released": {
                    "bytes": 2449408
                },
                "stack": {
                    "bytes": 524288
                },
                "total": {
                    "bytes": 3670016
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
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
