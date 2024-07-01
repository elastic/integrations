# Cassandra Integration

This integration periodically fetches metrics from [Cassandra](https://cassandra.apache.org/) using jolokia agent. It can parse System logs.

## Compatibility

This integration has been tested against `Cassandra version 3.11.11`.

## Steps to Setup Jolokia

### Prerequisites

- Java Development Kit (JDK) 1.8 or later
- Apache Cassandra 3.x or 4.x (depending on user's version)
- Jolokia agent JAR file

### Jolokia Setup

Follow these steps to set up Jolokia for monitoring Apache Cassandra:

1. Download the Jolokia JVM Agent:

   Visit the [Jolokia official download page](https://repo1.maven.org/maven2/org/jolokia/jolokia-jvm/) to obtain the latest version of the Jolokia JVM agent JAR file. Download the `jolokia-jvm-<jolokia_version>-agent.jar` file.

2. Copy the Jolokia Agent to Cassandra's Library Directory:

   Copy the downloaded `jolokia-jvm-<jolokia_version>-agent.jar` file to the Cassandra library directory on the server where Cassandra is installed.

   For example:

   ```bash
   cp jolokia-jvm-<jolokia_version>-agent.jar /path/to/cassandra/lib/
   ```

   Replace `/path/to/cassandra/lib/` with the actual path to Cassandra's library directory.

3. Configure Cassandra to use the Jolokia Agent:

   Open the `cassandra-env.sh` file, located in the Cassandra configuration directory, using a text editor, and add the following line at the bottom of the file:

   ```
   JVM_OPTS="$JVM_OPTS -javaagent:/path/to/jolokia-jvm-<jolokia_version>-agent.jar=port=<jolokia_port>,host=0.0.0.0"
   ```

   Replace `/path/to/jolokia-jvm-<version>-agent.jar` with the actual path to the Jolokia agent JAR file copied in Step 2. Save the changes and close the `cassandra-env.sh` file.

4. Restart Cassandra:

   Restart the Apache Cassandra service to apply the changes made to the configuration.

   > Note:
   - Restarting the Apache Cassandra service will temporarily disrupt database connectivity. Ensure that dependent services are designed to handle such interruptions gracefully.
   - Immediately after a restart, Cassandra's performance may be impacted due to cold caches and commit log replay. Allow some time for the system to stabilize.
   - Before restarting Cassandra, ensure that no cluster maintenance tasks are in progress to prevent any unintended consequences.
   - The exact steps will vary based on the installation type, the setup process might differ based on the specific deployment method or environment.
   - Procedures for restarting Cassandra may vary based on user's specific setup and configuration.

## Verifying the setup

After restarting Cassandra, user can verify that Jolokia is properly set up by accessing the Jolokia endpoint:

```
http://<cassandra-host>:<jolokia_port>/jolokia
```

Replace with the hostname or IP address of user's Cassandra server.

If the setup is successful, user should see a JSON response containing information about the available Jolokia operations and the Cassandra instance.

User can now use Jolokia to monitor and manage Apache Cassandra cluster.

## Troubleshooting

- If `log.flags` appears conflicted under the ``logs-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Logs`` data stream.

## Logs

Cassandra system logs from cassandra.log files.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-08-01T07:33:01.952Z",
    "agent": {
        "ephemeral_id": "d6102ad8-04fe-46fa-bf67-cc98e3665348",
        "hostname": "docker-fleet-agent",
        "id": "d1a9277c-e5a2-4ee3-a973-18f2b62e3ad8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.15.0"
    },
    "data_stream": {
        "dataset": "cassandra.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "d1a9277c-e5a2-4ee3-a973-18f2b62e3ad8",
        "snapshot": false,
        "version": "7.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "cassandra.log",
        "ingested": "2022-08-01T07:33:17Z",
        "kind": "event",
        "module": "cassandra",
        "original": "INFO  [main] 2022-08-01 07:33:01,952 YamlConfigurationLoader.java:92 - Configuration location: file:/etc/cassandra/cassandra.yaml",
        "type": "info"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/cassandra/system.log"
        },
        "level": "INFO",
        "offset": 0,
        "origin": {
            "file": {
                "line": 92,
                "name": "YamlConfigurationLoader.java"
            }
        }
    },
    "message": "Configuration location: file:/etc/cassandra/cassandra.yaml",
    "process": {
        "thread": {
            "name": "main"
        }
    },
    "tags": [
        "forwarded",
        "cassandra-systemlogs"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cassandra.log.meta | Log meta infos like java stack_trace. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.origin.file.line | The line number of the file containing the source code which originated the log event. | long |
| log.origin.file.name | The name of the file containing the source code which originated the log event. Note that this field is not meant to capture the log file. The correct field to capture the log file is `log.file.path`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.thread.name | Thread name. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

Cassandra metrics using jolokia agent installed on cassandra.

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2022-08-02T07:46:20.906Z",
    "agent": {
        "ephemeral_id": "dd01aaac-f888-4fdb-832d-d05840060d78",
        "hostname": "docker-fleet-agent",
        "id": "f8436de1-7850-497f-905d-b6c9ca3116ca",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.15.0"
    },
    "cassandra": {
        "metrics": {
            "cache": {
                "key_cache": {
                    "capacity": 104857600,
                    "one_minute_hit_rate": 0.7055988630359871,
                    "requests": {
                        "one_minute_rate": 10.000444146293233
                    }
                },
                "row_cache": {
                    "capacity": 0,
                    "requests": {
                        "one_minute_rate": 0
                    }
                }
            },
            "client": {
                "connected_native_clients": 0
            },
            "client_request": {
                "casread": {
                    "one_minute_rate": 0
                },
                "caswrite": {
                    "one_minute_rate": 0
                },
                "range_slice": {
                    "one_minute_rate": 0,
                    "total_latency": 0
                },
                "read": {
                    "count": 0,
                    "one_minute_rate": 0,
                    "timeouts": 0,
                    "timeoutsms": 0,
                    "total_latency": 0,
                    "unavailables": 0,
                    "unavailablesms": 0
                },
                "write": {
                    "count": 0,
                    "one_minute_rate": 0,
                    "timeouts": 0,
                    "timeoutsms": 0,
                    "total_latency": 0,
                    "unavailables": 0,
                    "unavailablesms": 0
                }
            },
            "column_family": {
                "total_disk_space_used": 72611
            },
            "compaction": {
                "completed": 45,
                "pending": 0
            },
            "dropped_message": {
                "batch_remove": 0,
                "batch_store": 0,
                "counter_mutation": 0,
                "hint": 0,
                "mutation": 0,
                "paged_range": 0,
                "range_slice": 0,
                "read": 0,
                "read_repair": 0,
                "request_response": 0,
                "trace": 0
            },
            "gc": {
                "concurrent_mark_sweep": {
                    "collection_count": 1,
                    "collection_time": 27
                },
                "par_new": {
                    "collection_count": 1,
                    "collection_time": 24
                }
            },
            "memory": {
                "heap_usage": {
                    "committed": 4054777856,
                    "init": 4158652416,
                    "max": 4054777856,
                    "used": 478032264
                },
                "other_usage": {
                    "committed": 62853120,
                    "init": 2555904,
                    "max": -1,
                    "used": 61234528
                }
            },
            "storage": {
                "exceptions": 0,
                "load": 72611,
                "total_hint_in_progress": 0,
                "total_hints": 0
            },
            "system": {
                "cluster": "Test Cluster",
                "data_center": "datacenter1",
                "live_nodes": [
                    "192.168.224.2"
                ],
                "rack": "rack1",
                "version": "3.11.11"
            },
            "table": {
                "all_memtables_heap_size": 4569,
                "all_memtables_off_heap_size": 0,
                "live_disk_space_used": 72611,
                "live_ss_table_count": 11
            },
            "task": {
                "complete": 55,
                "pending": 0,
                "total_commitlog_size": 67108864
            },
            "thread_pools": {
                "counter_mutation_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                },
                "mutation_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                },
                "read_repair_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                },
                "read_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                },
                "request_response_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "cassandra.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "f8436de1-7850-497f-905d-b6c9ca3116ca",
        "snapshot": false,
        "version": "7.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "created": "2022-08-02T07:46:20.906Z",
        "dataset": "cassandra.metrics",
        "duration": 13448617,
        "ingested": "2022-08-02T07:46:24Z",
        "kind": "event",
        "module": "cassandra",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "2cbd07697ac16c7d26f103cb3d40e3aa",
        "ip": [
            "192.168.192.7"
        ],
        "mac": [
            "02:42:c0:a8:c0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "3.10.0-1160.71.1.el7.x86_64",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_cassandra_1:8778/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cassandra.metrics.cache.key_cache.capacity |  | long | gauge |
| cassandra.metrics.cache.key_cache.one_minute_hit_rate |  | long | gauge |
| cassandra.metrics.cache.key_cache.requests.one_minute_rate |  | long | gauge |
| cassandra.metrics.cache.row_cache.capacity |  | long | gauge |
| cassandra.metrics.cache.row_cache.one_minute_hit_rate |  | long | gauge |
| cassandra.metrics.cache.row_cache.requests.one_minute_rate |  | long | gauge |
| cassandra.metrics.client.connected_native_clients |  | long | gauge |
| cassandra.metrics.client_request.casread.one_minute_rate |  | double | gauge |
| cassandra.metrics.client_request.caswrite.one_minute_rate |  | double | gauge |
| cassandra.metrics.client_request.range_slice.one_minute_rate |  | double | gauge |
| cassandra.metrics.client_request.range_slice.total_latency |  | double | counter |
| cassandra.metrics.client_request.read.count |  | long | counter |
| cassandra.metrics.client_request.read.one_minute_rate |  | double | gauge |
| cassandra.metrics.client_request.read.timeouts | Number of read timeouts encountered. | double | counter |
| cassandra.metrics.client_request.read.timeoutsms |  | double | gauge |
| cassandra.metrics.client_request.read.total_latency |  | double | counter |
| cassandra.metrics.client_request.read.unavailables | Number of read unavailables encountered. | double | counter |
| cassandra.metrics.client_request.read.unavailablesms |  | double | gauge |
| cassandra.metrics.client_request.write.count |  | long | counter |
| cassandra.metrics.client_request.write.one_minute_rate |  | double | gauge |
| cassandra.metrics.client_request.write.timeouts |  | double | counter |
| cassandra.metrics.client_request.write.timeoutsms |  | double | gauge |
| cassandra.metrics.client_request.write.total_latency |  | double | counter |
| cassandra.metrics.client_request.write.unavailables |  | double | counter |
| cassandra.metrics.client_request.write.unavailablesms |  | double | gauge |
| cassandra.metrics.column_family.total_disk_space_used |  | long | gauge |
| cassandra.metrics.compaction.completed | compaction completed tasks. | long | gauge |
| cassandra.metrics.compaction.pending | compaction pending tasks. | long | gauge |
| cassandra.metrics.dropped_message.batch_remove |  | long | counter |
| cassandra.metrics.dropped_message.batch_store |  | long | counter |
| cassandra.metrics.dropped_message.counter_mutation |  | long | counter |
| cassandra.metrics.dropped_message.hint |  | long | counter |
| cassandra.metrics.dropped_message.mutation |  | long | counter |
| cassandra.metrics.dropped_message.paged_range |  | long | counter |
| cassandra.metrics.dropped_message.range_slice |  | long | counter |
| cassandra.metrics.dropped_message.read |  | long | counter |
| cassandra.metrics.dropped_message.read_repair |  | long | counter |
| cassandra.metrics.dropped_message.request_response |  | long | counter |
| cassandra.metrics.dropped_message.trace |  | long | counter |
| cassandra.metrics.gc.concurrent_mark_sweep.collection_count | Total number of CMS collections that have occurred. | long | gauge |
| cassandra.metrics.gc.concurrent_mark_sweep.collection_time | Approximate accumulated CMS collection elapsed time in milliseconds. | long | gauge |
| cassandra.metrics.gc.par_new.collection_count | Total number of ParNew collections that have occurred. | long | gauge |
| cassandra.metrics.gc.par_new.collection_time | Approximate accumulated ParNew collection elapsed time in milliseconds. | long | gauge |
| cassandra.metrics.memory.heap_usage.committed | Committed heap memory usage. | long | gauge |
| cassandra.metrics.memory.heap_usage.init | Initial heap memory usage. | long | gauge |
| cassandra.metrics.memory.heap_usage.max | Max heap memory usage. | long | gauge |
| cassandra.metrics.memory.heap_usage.used | Used heap memory usage. | long | gauge |
| cassandra.metrics.memory.other_usage.committed | Committed non-heap memory usage. | long | gauge |
| cassandra.metrics.memory.other_usage.init | Initial non-heap memory usage. | long | gauge |
| cassandra.metrics.memory.other_usage.max | Max non-heap memory usage. | long | gauge |
| cassandra.metrics.memory.other_usage.used | Used non-heap memory usage. | long | gauge |
| cassandra.metrics.storage.exceptions | The number of the total exceptions. | long | counter |
| cassandra.metrics.storage.load | Storage used for Cassandra data in bytes. | long | counter |
| cassandra.metrics.storage.total_hint_in_progress | The number of the total hits in progress. | long | counter |
| cassandra.metrics.storage.total_hints | The number of the total hits. | long | counter |
| cassandra.metrics.system.cluster |  | keyword |  |
| cassandra.metrics.system.data_center |  | keyword |  |
| cassandra.metrics.system.joining_nodes |  | keyword |  |
| cassandra.metrics.system.leaving_nodes |  | keyword |  |
| cassandra.metrics.system.live_nodes |  | keyword |  |
| cassandra.metrics.system.moving_nodes |  | keyword |  |
| cassandra.metrics.system.rack |  | keyword |  |
| cassandra.metrics.system.unreachable_nodes |  | keyword |  |
| cassandra.metrics.system.version |  | keyword |  |
| cassandra.metrics.table.all_memtables_heap_size |  | long | gauge |
| cassandra.metrics.table.all_memtables_off_heap_size |  | long | gauge |
| cassandra.metrics.table.live_disk_space_used |  | long | counter |
| cassandra.metrics.table.live_ss_table_count |  | long | gauge |
| cassandra.metrics.task.complete | completed tasks. | long | gauge |
| cassandra.metrics.task.pending | pending tasks. | long | gauge |
| cassandra.metrics.task.total_commitlog_size | total commitlog size of tasks. | long | gauge |
| cassandra.metrics.thread_pools.counter_mutation_stage.request.active |  | long | gauge |
| cassandra.metrics.thread_pools.counter_mutation_stage.request.pending |  | long | gauge |
| cassandra.metrics.thread_pools.mutation_stage.request.active |  | long | gauge |
| cassandra.metrics.thread_pools.mutation_stage.request.pending |  | long | gauge |
| cassandra.metrics.thread_pools.read_repair_stage.request.active |  | long | gauge |
| cassandra.metrics.thread_pools.read_repair_stage.request.pending |  | long | gauge |
| cassandra.metrics.thread_pools.read_stage.request.active |  | long | gauge |
| cassandra.metrics.thread_pools.read_stage.request.pending |  | long | gauge |
| cassandra.metrics.thread_pools.request_response_stage.request.active |  | long | gauge |
| cassandra.metrics.thread_pools.request_response_stage.request.pending |  | long | gauge |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |

