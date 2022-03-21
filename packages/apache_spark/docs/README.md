# Apache Spark

The Apache Spark integration collects and parses data using the Jolokia Metricbeat Module.

## Compatibility

This module has been tested against `Apache Spark version 3.2.0`

## Requirements

In order to ingest data from Apache Spark, you must know the full hosts for the Master and Worker nodes.

In order to gather Spark statistics, we need to download and enable Jolokia JVM Agent.

```
cd /usr/share/java/
wget -O jolokia-agent.jar http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/1.3.6/jolokia-jvm-1.3.6-agent.jar
```

As far, as Jolokia JVM Agent is downloaded, we should configure Apache Spark, to use it as JavaAgent and expose metrics via HTTP/Json. Edit spark-env.sh. It should be in `/usr/local/spark/conf` and add following parameters (Assuming that spark install folder is /usr/local/spark, if not change the path to one on which Spark is installed):
```
export SPARK_MASTER_OPTS="$SPARK_MASTER_OPTS -javaagent:/usr/share/java/jolokia-agent.jar=config=/usr/local/spark/conf/jolokia-master.properties"
```

Now, create `/usr/local/spark/conf/jolokia-master.properties` file with following content:
```
host=0.0.0.0
port=7777
agentContext=/jolokia
backlog=100

policyLocation=file:///usr/local/spark/conf/jolokia.policy
historyMaxEntries=10
debug=false
debugMaxEntries=100
maxDepth=15
maxCollectionSize=1000
maxObjects=0
```

Now we need to create /usr/local/spark/conf/jolokia.policy with following content:
```
<?xml version="1.0" encoding="utf-8"?>
<restrict>
  <http>
    <method>get</method>
    <method>post</method>
  </http>
  <commands>
    <command>read</command>
  </commands>
</restrict>
```

Configure Agent with following in conf/bigdata.ini file:
```
[Spark-Master]
stats: http://127.0.0.1:7777/jolokia/read
```
Restart Spark master.

Follow the same set of steps for Spark Worker, Driver and Executor.

## Metrics

### Driver

This is the `driver` dataset.

An example event for `driver` looks as following:

```json
{
    "@timestamp": "2022-03-09T11:54:51.083Z",
    "agent": {
        "ephemeral_id": "ee411959-b7ce-4172-a203-7701ea051771",
        "id": "bb7da080-fbb3-4124-aef4-06eccf171318",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "apache_spark": {
        "metrics": {
            "driver": {
                "application": {
                    "name": "app-20220322011157-0169"
                },
                "tasks": {
                    "skipped": 0
                }
            }
        }
    },
    "data_stream": {
        "dataset": "apache_spark.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "bb7da080-fbb3-4124-aef4-06eccf171318",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.metrics",
        "duration": 89018916,
        "ingested": "2022-03-09T11:54:54Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.21.0.5"
        ],
        "mac": [
            "02:42:ac:15:00:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://apachesparkmaster:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.metrics.driver.application.name |  | keyword |
| apache_spark.metrics.driver.dag_schedular.job.active |  | long |
| apache_spark.metrics.driver.dag_schedular.job.all |  | long |
| apache_spark.metrics.driver.dag_schedular.stages.failed |  | long |
| apache_spark.metrics.driver.dag_schedular.stages.running |  | long |
| apache_spark.metrics.driver.dag_schedular.stages.waiting |  | long |
| apache_spark.metrics.driver.disk.space_used |  | long |
| apache_spark.metrics.driver.executor_metrics.direct_pool_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.jvm.heap_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.jvm.off_heap_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.major_gc.count |  | long |
| apache_spark.metrics.driver.executor_metrics.major_gc.time |  | long |
| apache_spark.metrics.driver.executor_metrics.mappped_pool_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.minor_gc.count |  | long |
| apache_spark.metrics.driver.executor_metrics.minor_gc.time |  | long |
| apache_spark.metrics.driver.executor_metrics.off_heap.execution_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.off_heap.storage_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.off_heap.unified_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.on_heap.execution_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.on_heap.storage_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.on_heap.unified_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.process_tree.jvm.rss_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.process_tree.jvm.v_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.process_tree.other.rss_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.process_tree.other.v_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.process_tree.python.rss_memory |  | long |
| apache_spark.metrics.driver.executor_metrics.process_tree.python.v_memory |  | long |
| apache_spark.metrics.driver.executors.all |  | long |
| apache_spark.metrics.driver.executors.decommission_unfinished |  | long |
| apache_spark.metrics.driver.executors.exited_unexpectedly |  | long |
| apache_spark.metrics.driver.executors.gracefully_decommissioned |  | long |
| apache_spark.metrics.driver.executors.killed_by_driver |  | long |
| apache_spark.metrics.driver.executors.max_needed |  | long |
| apache_spark.metrics.driver.executors.pending_to_remove |  | long |
| apache_spark.metrics.driver.executors.target |  | long |
| apache_spark.metrics.driver.executors.to_add |  | long |
| apache_spark.metrics.driver.hive_external_catalog.file_cache_hits |  | long |
| apache_spark.metrics.driver.hive_external_catalog.files_discovered |  | long |
| apache_spark.metrics.driver.hive_external_catalog.hive_client_calls |  | long |
| apache_spark.metrics.driver.hive_external_catalog.parallel_listing_job.count |  | long |
| apache_spark.metrics.driver.hive_external_catalog.partitions_fetched |  | long |
| apache_spark.metrics.driver.job_duration |  | long |
| apache_spark.metrics.driver.jobs.failed |  | long |
| apache_spark.metrics.driver.jobs.succeeded |  | long |
| apache_spark.metrics.driver.jvm.cpu.time |  | long |
| apache_spark.metrics.driver.live_listener_bus.num_events_posted |  | long |
| apache_spark.metrics.driver.live_listener_bus.queue.app_status.dropped_events.count |  | long |
| apache_spark.metrics.driver.live_listener_bus.queue.app_status.size |  | long |
| apache_spark.metrics.driver.live_listener_bus.queue.event_logs.dropped_events.count |  | long |
| apache_spark.metrics.driver.live_listener_bus.queue.event_logs.size |  | long |
| apache_spark.metrics.driver.live_listener_bus.queue.executor_management.dropped_events.count |  | long |
| apache_spark.metrics.driver.live_listener_bus.queue.executor_management.size |  | long |
| apache_spark.metrics.driver.memory.max_mem |  | long |
| apache_spark.metrics.driver.memory.off_heap.max |  | long |
| apache_spark.metrics.driver.memory.off_heap.remaining |  | long |
| apache_spark.metrics.driver.memory.off_heap.used |  | long |
| apache_spark.metrics.driver.memory.on_heap.max |  | long |
| apache_spark.metrics.driver.memory.on_heap.remaining |  | long |
| apache_spark.metrics.driver.memory.on_heap.used |  | long |
| apache_spark.metrics.driver.memory.remaining |  | long |
| apache_spark.metrics.driver.memory.used |  | long |
| apache_spark.metrics.driver.spark.streaming.event_time.watermark |  | long |
| apache_spark.metrics.driver.spark.streaming.input_rate.total |  | double |
| apache_spark.metrics.driver.spark.streaming.latency |  | long |
| apache_spark.metrics.driver.spark.streaming.processing_rate.total |  | double |
| apache_spark.metrics.driver.spark.streaming.states.rows.total |  | long |
| apache_spark.metrics.driver.spark.streaming.states.used_bytes |  | long |
| apache_spark.metrics.driver.stages.completed_count |  | long |
| apache_spark.metrics.driver.stages.failed_count |  | long |
| apache_spark.metrics.driver.stages.skipped_count |  | long |
| apache_spark.metrics.driver.tasks.completed |  | long |
| apache_spark.metrics.driver.tasks.executors.black_listed |  | long |
| apache_spark.metrics.driver.tasks.executors.excluded |  | long |
| apache_spark.metrics.driver.tasks.executors.unblack_listed |  | long |
| apache_spark.metrics.driver.tasks.executors.unexcluded |  | long |
| apache_spark.metrics.driver.tasks.failed |  | long |
| apache_spark.metrics.driver.tasks.killed |  | long |
| apache_spark.metrics.driver.tasks.skipped |  | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Executors

This is the `executors` dataset.

An example event for `executors` looks as following:

```json
{
    "@timestamp": "2022-03-09T11:54:51.083Z",
    "agent": {
        "ephemeral_id": "ee411959-b7ce-4172-a203-7701ea051771",
        "id": "bb7da080-fbb3-4124-aef4-06eccf171318",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "apache_spark": {
        "metrics": {
            "executor": {
                "application": {
                    "name": "app-20220322011157-0169"
                },
                "id": "0",
                "filesystem": {
                    "hdfs": {
                        "write_bytes": 0
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "apache_spark.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "bb7da080-fbb3-4124-aef4-06eccf171318",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.metrics",
        "duration": 89018916,
        "ingested": "2022-03-09T11:54:54Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.21.0.5"
        ],
        "mac": [
            "02:42:ac:15:00:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://apachesparkmaster:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.metrics.executor.application.name |  | keyword |
| apache_spark.metrics.executor.bytes.read |  | long |
| apache_spark.metrics.executor.bytes.written |  | long |
| apache_spark.metrics.executor.compilation_time |  | long |
| apache_spark.metrics.executor.cpu_time |  | long |
| apache_spark.metrics.executor.deserialize.cpu_time |  | long |
| apache_spark.metrics.executor.deserialize.time |  | long |
| apache_spark.metrics.executor.direct_pool_memory |  | long |
| apache_spark.metrics.executor.disk_bytes_spilled |  | long |
| apache_spark.metrics.executor.file_cache_hits |  | long |
| apache_spark.metrics.executor.files_discovered |  | long |
| apache_spark.metrics.executor.filesystem.file.large_read_ops |  | long |
| apache_spark.metrics.executor.filesystem.file.read_bytes |  | long |
| apache_spark.metrics.executor.filesystem.file.read_ops |  | long |
| apache_spark.metrics.executor.filesystem.file.write_bytes |  | long |
| apache_spark.metrics.executor.filesystem.file.write_ops |  | long |
| apache_spark.metrics.executor.filesystem.hdfs.large_read_ops |  | long |
| apache_spark.metrics.executor.filesystem.hdfs.read_bytes |  | long |
| apache_spark.metrics.executor.filesystem.hdfs.read_ops |  | long |
| apache_spark.metrics.executor.filesystem.hdfs.write_bytes |  | long |
| apache_spark.metrics.executor.filesystem.hdfs.write_ops |  | long |
| apache_spark.metrics.executor.generated_class_size |  | long |
| apache_spark.metrics.executor.generated_method_size |  | long |
| apache_spark.metrics.executor.hive_client_calls |  | long |
| apache_spark.metrics.executor.id |  | keyword |
| apache_spark.metrics.executor.jvm.cpu_time |  | long |
| apache_spark.metrics.executor.jvm.gc_time |  | long |
| apache_spark.metrics.executor.jvm.heap_memory |  | long |
| apache_spark.metrics.executor.jvm.off_heap_memory |  | long |
| apache_spark.metrics.executor.major_gc.count |  | long |
| apache_spark.metrics.executor.major_gc.time |  | long |
| apache_spark.metrics.executor.mapped_pool_memory |  | long |
| apache_spark.metrics.executor.memory_bytes_spilled |  | long |
| apache_spark.metrics.executor.minor_gc.count |  | long |
| apache_spark.metrics.executor.minor_gc.time |  | long |
| apache_spark.metrics.executor.shuffle.bytes_written |  | long |
| apache_spark.metrics.executor.shuffle.client.used.direct_memory |  | long |
| apache_spark.metrics.executor.shuffle.client.used.heap_memory |  | long |
| apache_spark.metrics.executor.shuffle.fetch_wait_time |  | long |
| apache_spark.metrics.executor.shuffle.local.blocks_fetched |  | long |
| apache_spark.metrics.executor.shuffle.local.bytes_read |  | long |
| apache_spark.metrics.executor.shuffle.records.read |  | long |
| apache_spark.metrics.executor.shuffle.records.written |  | long |
| apache_spark.metrics.executor.shuffle.remote.blocks_fetched |  | long |
| apache_spark.metrics.executor.shuffle.remote.bytes_read |  | long |
| apache_spark.metrics.executor.shuffle.remote.bytes_read_to_disk |  | long |
| apache_spark.metrics.executor.shuffle.server.used.direct_memory |  | long |
| apache_spark.metrics.executor.shuffle.server.used.heap_memory |  | long |
| apache_spark.metrics.executor.shuffle.total.bytes_read |  | long |
| apache_spark.metrics.executor.shuffle.write.time |  | long |
| apache_spark.metrics.executor.source_code_size |  | long |
| apache_spark.metrics.executor.succeeded_tasks |  | long |
| apache_spark.metrics.executor.threadpool.active_tasks |  | long |
| apache_spark.metrics.executor.threadpool.complete_tasks |  | long |
| apache_spark.metrics.executor.threadpool.current_pool_size |  | long |
| apache_spark.metrics.executor.threadpool.max_pool_size |  | long |
| apache_spark.metrics.executor.threadpool.started_tasks |  | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Applications

This is the `applications` dataset.

An example event for `applications` looks as following:

```json
{
    "@timestamp": "2022-03-09T11:54:51.083Z",
    "agent": {
        "ephemeral_id": "ee411959-b7ce-4172-a203-7701ea051771",
        "id": "bb7da080-fbb3-4124-aef4-06eccf171318",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "apache_spark": {
        "metrics": {
            "application_source": {
                "cores": 8,
                "name": "JavaWordCount.1646133990496"
            }
        }
    },
    "data_stream": {
        "dataset": "apache_spark.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "bb7da080-fbb3-4124-aef4-06eccf171318",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.metrics",
        "duration": 89018916,
        "ingested": "2022-03-09T11:54:54Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.21.0.5"
        ],
        "mac": [
            "02:42:ac:15:00:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://apachesparkmaster:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.metrics.application_source.cores | Number of cores. | long |
| apache_spark.metrics.application_source.name | Name of the application. | keyword |
| apache_spark.metrics.application_source.runtime_ms | Time taken to run the application (ms). | long |
| apache_spark.metrics.application_source.status | Current status of the application. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Nodes

This is the `nodes` dataset.

An example event for `nodes` looks as following:

```json
{
    "@timestamp": "2022-03-21T16:08:10.415Z",
    "agent": {
        "ephemeral_id": "69f2897f-0e6c-4a75-af87-2f038ed77224",
        "id": "00ce5157-ceb1-4a57-9e48-be5b4efc407f",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "apache_spark": {
        "metrics": {
            "master": {
                "apps": {
                    "count": 0,
                    "waiting": 0
                },
                "workers": {
                    "alive": 0,
                    "count": 0
                }
            }
        }
    },
    "data_stream": {
        "dataset": "apache_spark.nodes",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "00ce5157-ceb1-4a57-9e48-be5b4efc407f",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.nodes",
        "duration": 9054044,
        "ingested": "2022-03-21T16:08:13Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.23.0.5"
        ],
        "mac": [
            "02:42:ac:17:00:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://apachesparkmaster:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.metrics.master.apps.count | Total number of apps. | long |
| apache_spark.metrics.master.apps.waiting | Number of apps waiting. | long |
| apache_spark.metrics.master.workers.alive | Number of alive workers. | long |
| apache_spark.metrics.master.workers.count | Total number of workers. | long |
| apache_spark.metrics.worker.cores.free | Number of cores free. | long |
| apache_spark.metrics.worker.cores.used | Number of cores used. | long |
| apache_spark.metrics.worker.executors | Number of executors. | long |
| apache_spark.metrics.worker.memory.free | Number of cores free. | long |
| apache_spark.metrics.worker.memory.used | Amount of memory utilized in MB. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

