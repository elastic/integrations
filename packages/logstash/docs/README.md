# Logstash

The `logstash` package collects metrics and logs of Logstash.

## Compatibility

The `logstash` package works with Logstash 8.5.0 and later

## Logs

Logstash package supports the plain text format and the JSON format. Also, two types of 
logs can be activated with the Logstash package:

* `log` collects and parses the logs that Logstash writes to disk.
* `slowlog` parses the logstash slowlog (make sure to configure the Logstash slowlog option).

#### Known issues

When using the `log` data stream to parse plaintext logs, if a multiline plaintext log contains an embedded JSON object such that
the JSON object starts on a new line, the fileset may not parse the multiline plaintext log event correctly.


## Metrics

Logstash metric related data streams works with Logstash 7.3.0 and later.

### Node Stats

An example event for `node_stats` looks as following:

```json
{
    "@timestamp": "2022-10-11T14:05:39.791Z",
    "agent": {
        "ephemeral_id": "1a1ca75b-a20f-4ae4-82a9-4e269c855a5d",
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "logstash.stack_monitoring.node_stats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "snapshot": true,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "logstash.stack_monitoring.node_stats",
        "duration": 125822375,
        "ingested": "2022-10-11T14:05:40Z",
        "module": "logstash"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "b6bc6723e51b43959ce07f0c3105c72d",
        "ip": [
            "192.168.0.7"
        ],
        "mac": [
            "02-42-C0-A8-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "logstash": {
        "cluster": {
            "id": "U8DCOXCFQHWlaKczNT4LNQ"
        },
        "elasticsearch": {
            "cluster": {
                "id": "U8DCOXCFQHWlaKczNT4LNQ"
            }
        },
        "node": {
            "stats": {
                "events": {
                    "duration_in_millis": 322,
                    "filtered": 132,
                    "in": 593,
                    "out": 132
                },
                "jvm": {
                    "gc": {
                        "collectors": {
                            "old": {
                                "collection_count": 0,
                                "collection_time_in_millis": 0
                            },
                            "young": {
                                "collection_count": 25,
                                "collection_time_in_millis": 269
                            }
                        }
                    },
                    "mem": {
                        "heap_max_in_bytes": 3137339390,
                        "heap_used_in_bytes": 208271008,
                        "heap_used_percent": 6
                    },
                    "uptime_in_millis": 17121
                },
                "logstash": {
                    "ephemeral_id": "59ea6513-500d-4b0b-8d54-a32d94631b1f",
                    "host": "ee237ad022ba",
                    "http_address": "0.0.0.0:9600",
                    "name": "ee237ad022ba",
                    "pipeline": {
                        "batch_size": 125,
                        "workers": 7
                    },
                    "snapshot": true,
                    "status": "green",
                    "uuid": "cb4f884e-d57b-43a3-bec6-7b3ec1adcbb9",
                    "version": "8.5.0"
                },
                "os": {
                    "cgroup": {
                        "cpu": {
                            "control_group": "",
                            "stat": null
                        },
                        "cpuacct": null
                    },
                    "cpu": {
                        "load_average": {
                            "15m": 2.17,
                            "1m": 3.32,
                            "5m": 2.32
                        },
                        "percent": 0
                    }
                },
                "pipelines": [
                    {
                        "ephemeral_id": "0eff59ef-d130-4753-bd4e-289341a84c1a",
                        "events": {
                            "duration_in_millis": 199,
                            "filtered": 86,
                            "in": 92,
                            "out": 86,
                            "queue_push_duration_in_millis": 4
                        },
                        "hash": "0542fa70daa36dc3e858ea099f125cc8c9e451ebbfe8ea8867e52f9764da0a35",
                        "id": "pipeline-with-memory-queue",
                        "queue": {
                            "events_count": 0,
                            "max_queue_size_in_bytes": 0,
                            "queue_size_in_bytes": 0,
                            "type": "memory"
                        },
                        "reloads": {
                            "failures": 0,
                            "successes": 0
                        },
                        "vertices": [
                            {
                                "events_out": 92,
                                "id": "4c5941552cdaa72ebc285557c697a7150c359ee3eacf9b5664c4b1048e26153b",
                                "pipeline_ephemeral_id": "0eff59ef-d130-4753-bd4e-289341a84c1a",
                                "queue_push_duration_in_millis": 4
                            },
                            {
                                "cluster_uuid": "U8DCOXCFQHWlaKczNT4LNQ",
                                "duration_in_millis": 197,
                                "events_in": 86,
                                "events_out": 86,
                                "id": "635a080aacc8700059852859da284a9cb92cb78a6d7112fbf55e441e51b6658a",
                                "long_counters": [
                                    {
                                        "name": "bulk_requests.successes",
                                        "value": 15
                                    },
                                    {
                                        "name": "bulk_requests.responses.200",
                                        "value": 15
                                    },
                                    {
                                        "name": "documents.successes",
                                        "value": 86
                                    }
                                ],
                                "pipeline_ephemeral_id": "0eff59ef-d130-4753-bd4e-289341a84c1a"
                            }
                        ]
                    },
                    {
                        "ephemeral_id": "5ba3b3b3-4d82-4877-b96e-f327335bf1e1",
                        "events": {
                            "duration_in_millis": 0,
                            "filtered": 0,
                            "in": 456,
                            "out": 0,
                            "queue_push_duration_in_millis": 52
                        },
                        "hash": "d83c53e142e85177df0f039e5b9f4575b858e9cfdd51c2c60b1a9e8d5f9b1aaa",
                        "id": "pipeline-with-persisted-queue",
                        "queue": {
                            "capacity": {
                                "max_queue_size_in_bytes": 1073741824,
                                "max_unread_events": 0,
                                "page_capacity_in_bytes": 67108864,
                                "queue_size_in_bytes": 139404
                            },
                            "data": {
                                "free_space_in_bytes": 170819031040,
                                "path": "/usr/share/logstash/data/queue/pipeline-with-persisted-queue",
                                "storage_type": "overlay"
                            },
                            "events": 0,
                            "events_count": 0,
                            "max_queue_size_in_bytes": 1073741824,
                            "queue_size_in_bytes": 139404,
                            "type": "persisted"
                        },
                        "reloads": {
                            "failures": 0,
                            "successes": 0
                        },
                        "vertices": [
                            {
                                "events_out": 456,
                                "id": "dfc132c40b9f5dbc970604f191cf87ee04b102b6f4be5a235436973dc7ea6368",
                                "pipeline_ephemeral_id": "5ba3b3b3-4d82-4877-b96e-f327335bf1e1",
                                "queue_push_duration_in_millis": 52
                            },
                            {
                                "duration_in_millis": 0,
                                "events_in": 375,
                                "events_out": 0,
                                "id": "e24d45cc4f3bb9981356480856120ed5f68127abbc3af7f47e7bca32460e5019",
                                "pipeline_ephemeral_id": "5ba3b3b3-4d82-4877-b96e-f327335bf1e1"
                            },
                            {
                                "cluster_uuid": "U8DCOXCFQHWlaKczNT4LNQ",
                                "duration_in_millis": 0,
                                "events_in": 0,
                                "events_out": 0,
                                "id": "9ba6577aa5c41a5ebcaae010b9a0ef44015ae68c624596ed924417d1701abc21",
                                "pipeline_ephemeral_id": "5ba3b3b3-4d82-4877-b96e-f327335bf1e1"
                            }
                        ]
                    }
                ],
                "process": {
                    "cpu": {
                        "percent": 3
                    },
                    "max_file_descriptors": 1048576,
                    "open_file_descriptors": 86
                },
                "queue": {
                    "events_count": 0
                },
                "reloads": {
                    "failures": 0,
                    "successes": 0
                },
                "timestamp": "2022-10-11T14:05:39.916Z"
            }
        }
    },
    "metricset": {
        "name": "node_stats",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-logstash-1:9600/_node/stats",
        "hostname": "ee237ad022ba",
        "id": "",
        "name": "logstash",
        "type": "logstash",
        "version": "8.5.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| logstash.node.jvm.version | Version | keyword |
| logstash.node.state.pipeline.hash |  | keyword |
| logstash.node.state.pipeline.id |  | keyword |
| logstash.node.stats.events.duration_in_millis |  | long |
| logstash.node.stats.events.filtered | Filtered events counter. | long |
| logstash.node.stats.events.in | Incoming events counter. | long |
| logstash.node.stats.events.out | Outgoing events counter. | long |
| logstash.node.stats.jvm.mem.heap_max_in_bytes |  | long |
| logstash.node.stats.jvm.mem.heap_used_in_bytes |  | long |
| logstash.node.stats.jvm.uptime_in_millis |  | long |
| logstash.node.stats.logstash.uuid |  | keyword |
| logstash.node.stats.logstash.version |  | keyword |
| logstash.node.stats.os.cgroup.cpu.stat.number_of_elapsed_periods |  | long |
| logstash.node.stats.os.cgroup.cpu.stat.number_of_times_throttled |  | long |
| logstash.node.stats.os.cgroup.cpu.stat.time_throttled_nanos |  | long |
| logstash.node.stats.os.cgroup.cpuacct.usage_nanos |  | long |
| logstash.node.stats.os.cpu.load_average.15m |  | long |
| logstash.node.stats.os.cpu.load_average.1m |  | long |
| logstash.node.stats.os.cpu.load_average.5m |  | long |
| logstash.node.stats.pipelines.events.duration_in_millis |  | long |
| logstash.node.stats.pipelines.events.out |  | long |
| logstash.node.stats.pipelines.hash |  | keyword |
| logstash.node.stats.pipelines.id |  | keyword |
| logstash.node.stats.pipelines.queue.events_count |  | long |
| logstash.node.stats.pipelines.queue.max_queue_size_in_bytes |  | long |
| logstash.node.stats.pipelines.queue.queue_size_in_bytes |  | long |
| logstash.node.stats.pipelines.queue.type |  | keyword |
| logstash.node.stats.pipelines.vertices.duration_in_millis |  | long |
| logstash.node.stats.pipelines.vertices.events_in |  | long |
| logstash.node.stats.pipelines.vertices.events_out | events_out | long |
| logstash.node.stats.pipelines.vertices.id | id | keyword |
| logstash.node.stats.pipelines.vertices.pipeline_ephemeral_id | pipeline_ephemeral_id | keyword |
| logstash.node.stats.pipelines.vertices.queue_push_duration_in_millis | queue_push_duration_in_millis | float |
| logstash.node.stats.process.cpu.percent |  | double |
| logstash.node.stats.queue.events_count |  | long |
| logstash_stats.pipelines |  | nested |
| process.pid | Process id. | long |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |

### Node

An example event for `node` looks as following:

```json
{
    "@timestamp": "2022-10-11T14:04:44.089Z",
    "agent": {
        "ephemeral_id": "1a1ca75b-a20f-4ae4-82a9-4e269c855a5d",
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "logstash.stack_monitoring.node",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "79e48fe3-2ecd-4021-aed5-6e7e69d47606",
        "snapshot": true,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "logstash.stack_monitoring.node",
        "duration": 131377542,
        "ingested": "2022-10-11T14:04:45Z",
        "module": "logstash"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "b6bc6723e51b43959ce07f0c3105c72d",
        "ip": [
            "192.168.0.7"
        ],
        "mac": [
            "02-42-C0-A8-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "logstash": {
        "cluster": {
            "id": "U8DCOXCFQHWlaKczNT4LNQ"
        },
        "elasticsearch": {
            "cluster": {
                "id": "U8DCOXCFQHWlaKczNT4LNQ"
            }
        },
        "node": {
            "host": "17a6005cfeaa",
            "id": "7d7ee953-cf82-4d1d-91e0-1714346531de",
            "jvm": {
                "version": "17.0.4"
            },
            "state": {
                "pipeline": {
                    "batch_size": 125,
                    "ephemeral_id": "3d2aff1f-dde1-4c56-9560-14f3b092f894",
                    "hash": "d83c53e142e85177df0f039e5b9f4575b858e9cfdd51c2c60b1a9e8d5f9b1aaa",
                    "id": "pipeline-with-persisted-queue",
                    "representation": {
                        "graph": {
                            "edges": [
                                {
                                    "from": "dfc132c40b9f5dbc970604f191cf87ee04b102b6f4be5a235436973dc7ea6368",
                                    "id": "9ed824e4f189b461c111ae27c17644c3c5f6d7c3c2bb213cbc7cc067cbd68fe6",
                                    "to": "__QUEUE__",
                                    "type": "plain"
                                },
                                {
                                    "from": "__QUEUE__",
                                    "id": "cb33f8fb7611e31a2c1751b74cdedf5b8cdb96ea46b812a2541e2db4f13dca10",
                                    "to": "e24d45cc4f3bb9981356480856120ed5f68127abbc3af7f47e7bca32460e5019",
                                    "type": "plain"
                                },
                                {
                                    "from": "e24d45cc4f3bb9981356480856120ed5f68127abbc3af7f47e7bca32460e5019",
                                    "id": "63ef166c45b87a40f31e0a6def175f10460b6b0ed656e70968eb52b1c454ab16",
                                    "to": "9ba6577aa5c41a5ebcaae010b9a0ef44015ae68c624596ed924417d1701abc21",
                                    "type": "plain"
                                }
                            ],
                            "vertices": [
                                {
                                    "config_name": "java_generator",
                                    "explicit_id": false,
                                    "id": "dfc132c40b9f5dbc970604f191cf87ee04b102b6f4be5a235436973dc7ea6368",
                                    "meta": {
                                        "source": {
                                            "column": 3,
                                            "id": "/usr/share/logstash/pipeline/persisted-queue.conf",
                                            "line": 2,
                                            "protocol": "file"
                                        }
                                    },
                                    "plugin_type": "input",
                                    "type": "plugin"
                                },
                                {
                                    "explicit_id": false,
                                    "id": "__QUEUE__",
                                    "meta": null,
                                    "type": "queue"
                                },
                                {
                                    "config_name": "sleep",
                                    "explicit_id": false,
                                    "id": "e24d45cc4f3bb9981356480856120ed5f68127abbc3af7f47e7bca32460e5019",
                                    "meta": {
                                        "source": {
                                            "column": 3,
                                            "id": "/usr/share/logstash/pipeline/persisted-queue.conf",
                                            "line": 8,
                                            "protocol": "file"
                                        }
                                    },
                                    "plugin_type": "filter",
                                    "type": "plugin"
                                },
                                {
                                    "config_name": "elasticsearch",
                                    "explicit_id": false,
                                    "id": "9ba6577aa5c41a5ebcaae010b9a0ef44015ae68c624596ed924417d1701abc21",
                                    "meta": {
                                        "source": {
                                            "column": 3,
                                            "id": "/usr/share/logstash/pipeline/persisted-queue.conf",
                                            "line": 15,
                                            "protocol": "file"
                                        }
                                    },
                                    "plugin_type": "output",
                                    "type": "plugin"
                                }
                            ]
                        },
                        "hash": "d83c53e142e85177df0f039e5b9f4575b858e9cfdd51c2c60b1a9e8d5f9b1aaa",
                        "type": "lir",
                        "version": "0.0.0"
                    },
                    "workers": 7
                }
            },
            "version": "8.5.0"
        }
    },
    "metricset": {
        "name": "node",
        "period": 10000
    },
    "process": {
        "pid": 1
    },
    "service": {
        "address": "http://elastic-package-service-logstash-1:9600/_node",
        "hostname": "17a6005cfeaa",
        "id": "7d7ee953-cf82-4d1d-91e0-1714346531de",
        "name": "logstash",
        "type": "logstash",
        "version": "8.5.0"
    }
}
```
