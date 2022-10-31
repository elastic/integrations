# Apache Spark Integration

The Apache Spark integration collects and parses data using the Jolokia Input.

## Compatibility

This integration has been tested against `Apache Spark version 3.2.0`

## Requirements

In order to ingest data from Apache Spark, you must know the full hosts for the Main and Worker nodes.

In order to gather Spark statistics, we need to download and enable Jolokia JVM Agent.

```
cd /usr/share/java/
wget -O jolokia-agent.jar http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/1.3.6/jolokia-jvm-1.3.6-agent.jar
```

As far, as Jolokia JVM Agent is downloaded, we should configure Apache Spark, to use it as JavaAgent and expose metrics via HTTP/JSON. Edit spark-env.sh. It should be in `/usr/local/spark/conf` and add following parameters (Assuming that spark install folder is `/usr/local/spark`, if not change the path to one on which Spark is installed):
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
```xml
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

### Application

This is the `application` data stream.

An example event for `application` looks as following:

```json
{
    "@timestamp": "2022-04-11T09:45:08.887Z",
    "agent": {
        "ephemeral_id": "fd3ce7d1-e237-45c7-88f9-875edafec41e",
        "id": "e7990c69-6909-48d1-be06-89dbe36d302c",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "apache_spark": {
        "application": {
            "name": "PythonWordCount.1649670292906",
            "runtime": {
                "ms": 16007
            }
        }
    },
    "data_stream": {
        "dataset": "apache_spark.application",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "e7990c69-6909-48d1-be06-89dbe36d302c",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.application",
        "duration": 21401735,
        "ingested": "2022-04-11T09:45:12Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.0.5"
        ],
        "mac": [
            "02:42:c0:a8:00:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-107-generic",
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
        "address": "http://apache-spark-main:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.application.cores | Number of cores. | long |
| apache_spark.application.name | Name of the application. | keyword |
| apache_spark.application.runtime.ms | Time taken to run the application (ms). | long |
| apache_spark.application.status | Current status of the application. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Driver

This is the `driver` data stream.

An example event for `driver` looks as following:

```json
{
    "@timestamp": "2022-04-06T09:28:29.830Z",
    "agent": {
        "ephemeral_id": "0136f072-d8da-429f-92f9-310435dbeb07",
        "id": "b92a6ed6-a92c-4064-9b78-b3b21cab191c",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "apache_spark": {
        "driver": {
            "application_name": "app-20220406092805-0000",
            "executor_metrics": {
                "memory": {
                    "jvm": {
                        "heap": 288770488
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "apache_spark.driver",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "b92a6ed6-a92c-4064-9b78-b3b21cab191c",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.driver",
        "duration": 51414715,
        "ingested": "2022-04-06T09:28:33Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.80.7"
        ],
        "mac": [
            "02:42:c0:a8:50:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-100-generic",
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
        "address": "http://apache-spark-main:7779/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.driver.application_name | Name of the application. | keyword |
| apache_spark.driver.dag_scheduler.job.active | Number of active jobs. | long |
| apache_spark.driver.dag_scheduler.job.all | Total number of jobs. | long |
| apache_spark.driver.dag_scheduler.stages.failed | Number of failed stages. | long |
| apache_spark.driver.dag_scheduler.stages.running | Number of running stages. | long |
| apache_spark.driver.dag_scheduler.stages.waiting | Number of waiting stages | long |
| apache_spark.driver.disk.space_used | Amount of the disk space utilized in MB. | long |
| apache_spark.driver.executor_metrics.gc.major.count | Total major GC count. For example, the garbage collector is one of MarkSweepCompact, PS MarkSweep, ConcurrentMarkSweep, G1 Old Generation and so on. | long |
| apache_spark.driver.executor_metrics.gc.major.time | Elapsed total major GC time. The value is expressed in milliseconds. | long |
| apache_spark.driver.executor_metrics.gc.minor.count | Total minor GC count. For example, the garbage collector is one of Copy, PS Scavenge, ParNew, G1 Young Generation and so on. | long |
| apache_spark.driver.executor_metrics.gc.minor.time | Elapsed total minor GC time. The value is expressed in milliseconds. | long |
| apache_spark.driver.executor_metrics.heap_memory.off.execution | Peak off heap execution memory in use, in bytes. | long |
| apache_spark.driver.executor_metrics.heap_memory.off.storage | Peak off heap storage memory in use, in bytes. | long |
| apache_spark.driver.executor_metrics.heap_memory.off.unified | Peak off heap memory (execution and storage). | long |
| apache_spark.driver.executor_metrics.heap_memory.on.execution | Peak on heap execution memory in use, in bytes. | long |
| apache_spark.driver.executor_metrics.heap_memory.on.storage | Peak on heap storage memory in use, in bytes. | long |
| apache_spark.driver.executor_metrics.heap_memory.on.unified | Peak on heap memory (execution and storage). | long |
| apache_spark.driver.executor_metrics.memory.direct_pool | Peak memory that the JVM is using for direct buffer pool. | long |
| apache_spark.driver.executor_metrics.memory.jvm.heap | Peak memory usage of the heap that is used for object allocation. | long |
| apache_spark.driver.executor_metrics.memory.jvm.off_heap | Peak memory usage of non-heap memory that is used by the Java virtual machine. | long |
| apache_spark.driver.executor_metrics.memory.mapped_pool | Peak memory that the JVM is using for mapped buffer pool | long |
| apache_spark.driver.executor_metrics.process_tree.jvm.rss_memory | Resident Set Size: number of pages the process has in real memory. This is just the pages which count toward text, data, or stack space. This does not include pages which have not been demand-loaded in, or which are swapped out. | long |
| apache_spark.driver.executor_metrics.process_tree.jvm.v_memory | Virtual memory size in bytes. | long |
| apache_spark.driver.executor_metrics.process_tree.other.rss_memory |  | long |
| apache_spark.driver.executor_metrics.process_tree.other.v_memory |  | long |
| apache_spark.driver.executor_metrics.process_tree.python.rss_memory |  | long |
| apache_spark.driver.executor_metrics.process_tree.python.v_memory |  | long |
| apache_spark.driver.executors.all | Total number of executors. | long |
| apache_spark.driver.executors.decommission_unfinished | Total number of decommissioned unfinished executors. | long |
| apache_spark.driver.executors.exited_unexpectedly | Total number of executors exited unexpectedly. | long |
| apache_spark.driver.executors.gracefully_decommissioned | Total number of executors gracefully decommissioned. | long |
| apache_spark.driver.executors.killed_by_driver | Total number of executors killed by driver. | long |
| apache_spark.driver.executors.max_needed | Maximum number of executors needed. | long |
| apache_spark.driver.executors.pending_to_remove | Total number of executors pending to be removed. | long |
| apache_spark.driver.executors.target | Total number of target executors. | long |
| apache_spark.driver.executors.to_add | Total number of executors to be added. | long |
| apache_spark.driver.hive_external_catalog.file_cache_hits | Total number of file cache hits. | long |
| apache_spark.driver.hive_external_catalog.files_discovered | Total number of files discovered. | long |
| apache_spark.driver.hive_external_catalog.hive_client_calls | Total number of Hive Client calls. | long |
| apache_spark.driver.hive_external_catalog.parallel_listing_job.count | Number of jobs running parallely. | long |
| apache_spark.driver.hive_external_catalog.partitions_fetched | Number of partitions fetched. | long |
| apache_spark.driver.job_duration | Duration of the job. | long |
| apache_spark.driver.jobs.failed | Number of failed jobs. | long |
| apache_spark.driver.jobs.succeeded | Number of successful jobs. | long |
| apache_spark.driver.jvm.cpu.time | Elapsed CPU time the JVM spent. | long |
| apache_spark.driver.memory.max_mem | Maximum amount of memory available for storage, in MB. | long |
| apache_spark.driver.memory.off_heap.max | Maximum amount of off heap memory available, in MB. | long |
| apache_spark.driver.memory.off_heap.remaining | Remaining amount of off heap memory, in MB. | long |
| apache_spark.driver.memory.off_heap.used | Total amount of off heap memory used, in MB. | long |
| apache_spark.driver.memory.on_heap.max | Maximum amount of on heap memory available, in MB. | long |
| apache_spark.driver.memory.on_heap.remaining | Remaining amount of on heap memory, in MB. | long |
| apache_spark.driver.memory.on_heap.used | Total amount of on heap memory used, in MB. | long |
| apache_spark.driver.memory.remaining | Remaining amount of storage memory, in MB. | long |
| apache_spark.driver.memory.used | Total amount of memory used for storage, in MB. | long |
| apache_spark.driver.spark.streaming.event_time.watermark |  | long |
| apache_spark.driver.spark.streaming.input_rate.total | Total rate of the input. | double |
| apache_spark.driver.spark.streaming.latency |  | long |
| apache_spark.driver.spark.streaming.processing_rate.total | Total rate of processing. | double |
| apache_spark.driver.spark.streaming.states.rows.total | Total number of rows. | long |
| apache_spark.driver.spark.streaming.states.used_bytes | Total number of bytes utilized. | long |
| apache_spark.driver.stages.completed_count | Total number of completed stages. | long |
| apache_spark.driver.stages.failed_count | Total number of failed stages. | long |
| apache_spark.driver.stages.skipped_count | Total number of skipped stages. | long |
| apache_spark.driver.tasks.completed | Number of completed tasks. | long |
| apache_spark.driver.tasks.executors.black_listed | Number of blacklisted executors for the tasks. | long |
| apache_spark.driver.tasks.executors.excluded | Number of excluded executors for the tasks. | long |
| apache_spark.driver.tasks.executors.unblack_listed | Number of unblacklisted executors for the tasks. | long |
| apache_spark.driver.tasks.executors.unexcluded | Number of unexcluded executors for the tasks. | long |
| apache_spark.driver.tasks.failed | Number of failed tasks. | long |
| apache_spark.driver.tasks.killed | Number of killed tasks. | long |
| apache_spark.driver.tasks.skipped | Number of skipped tasks. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Executor

This is the `executor` data stream.

An example event for `executor` looks as following:

```json
{
    "@timestamp": "2022-04-11T08:29:56.056Z",
    "agent": {
        "ephemeral_id": "c7d892ac-3b23-471c-80e4-041490eaab8d",
        "id": "c5e2a51e-e10a-4561-9861-75b38aa09f4b",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "apache_spark": {
        "executor": {
            "application_name": "app-20220411082945-0000",
            "gc": {
                "major": {
                    "count": 0
                }
            },
            "id": "0"
        }
    },
    "data_stream": {
        "dataset": "apache_spark.executor",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "c5e2a51e-e10a-4561-9861-75b38aa09f4b",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.executor",
        "duration": 32964497,
        "ingested": "2022-04-11T08:29:59Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
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
            "kernel": "5.4.0-107-generic",
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
        "address": "http://apache-spark-main:7780/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.executor.application_name | Name of application. | keyword |
| apache_spark.executor.bytes.read | Total number of bytes read. | long |
| apache_spark.executor.bytes.written | Total number of bytes written. | long |
| apache_spark.executor.disk_bytes_spilled | Total number of disk bytes spilled. | long |
| apache_spark.executor.file_cache_hits | Total number of file cache hits. | long |
| apache_spark.executor.files_discovered | Total number of files discovered. | long |
| apache_spark.executor.filesystem.file.large_read_ops | Total number of large read operations from the files. | long |
| apache_spark.executor.filesystem.file.read_bytes | Total number of bytes read from the files. | long |
| apache_spark.executor.filesystem.file.read_ops | Total number of read operations from the files. | long |
| apache_spark.executor.filesystem.file.write_bytes | Total number of bytes written from the files. | long |
| apache_spark.executor.filesystem.file.write_ops | Total number of write operations from the files. | long |
| apache_spark.executor.filesystem.hdfs.large_read_ops | Total number of large read operations from HDFS. | long |
| apache_spark.executor.filesystem.hdfs.read_bytes | Total number of read bytes from HDFS. | long |
| apache_spark.executor.filesystem.hdfs.read_ops | Total number of read operations from HDFS. | long |
| apache_spark.executor.filesystem.hdfs.write_bytes | Total number of write bytes from HDFS. | long |
| apache_spark.executor.filesystem.hdfs.write_ops | Total number of write operations from HDFS. | long |
| apache_spark.executor.gc.major.count | Total major GC count. For example, the garbage collector is one of MarkSweepCompact, PS MarkSweep, ConcurrentMarkSweep, G1 Old Generation and so on. | long |
| apache_spark.executor.gc.major.time | Elapsed total major GC time. The value is expressed in milliseconds. | long |
| apache_spark.executor.gc.minor.count | Total minor GC count. For example, the garbage collector is one of Copy, PS Scavenge, ParNew, G1 Young Generation and so on. | long |
| apache_spark.executor.gc.minor.time | Elapsed total minor GC time. The value is expressed in milliseconds. | long |
| apache_spark.executor.heap_memory.off.execution | Peak off heap execution memory in use, in bytes. | long |
| apache_spark.executor.heap_memory.off.storage | Peak off heap storage memory in use, in bytes. | long |
| apache_spark.executor.heap_memory.off.unified | Peak off heap memory (execution and storage). | long |
| apache_spark.executor.heap_memory.on.execution | Peak on heap execution memory in use, in bytes. | long |
| apache_spark.executor.heap_memory.on.storage | Peak on heap storage memory in use, in bytes. | long |
| apache_spark.executor.heap_memory.on.unified | Peak on heap memory (execution and storage). | long |
| apache_spark.executor.hive_client_calls | Total number of Hive Client calls. | long |
| apache_spark.executor.id | ID of executor. | keyword |
| apache_spark.executor.jvm.cpu_time | Elapsed CPU time the JVM spent. | long |
| apache_spark.executor.jvm.gc_time | Elapsed time the JVM spent in garbage collection while executing this task. | long |
| apache_spark.executor.memory.direct_pool | Peak memory that the JVM is using for direct buffer pool. | long |
| apache_spark.executor.memory.jvm.heap | Peak memory usage of the heap that is used for object allocation. | long |
| apache_spark.executor.memory.jvm.off_heap | Peak memory usage of non-heap memory that is used by the Java virtual machine. | long |
| apache_spark.executor.memory.mapped_pool | Peak memory that the JVM is using for mapped buffer pool | long |
| apache_spark.executor.memory_bytes_spilled | The number of in-memory bytes spilled by this task. | long |
| apache_spark.executor.parallel_listing_job_count | Number of jobs running parallely. | long |
| apache_spark.executor.partitions_fetched | Number of partitions fetched. | long |
| apache_spark.executor.process_tree.jvm.rss_memory | Resident Set Size: number of pages the process has in real memory. This is just the pages which count toward text, data, or stack space. This does not include pages which have not been demand-loaded in, or which are swapped out. | long |
| apache_spark.executor.process_tree.jvm.v_memory | Virtual memory size in bytes. | long |
| apache_spark.executor.process_tree.other.rss_memory | Resident Set Size for other kind of process. | long |
| apache_spark.executor.process_tree.other.v_memory | Virtual memory size for other kind of process in bytes. | long |
| apache_spark.executor.process_tree.python.rss_memory | Resident Set Size for Python. | long |
| apache_spark.executor.process_tree.python.v_memory | Virtual memory size for Python in bytes. | long |
| apache_spark.executor.records.read | Total number of records read. | long |
| apache_spark.executor.records.written | Total number of records written. | long |
| apache_spark.executor.result.serialization_time | Elapsed time spent serializing the task result. The value is expressed in milliseconds. | long |
| apache_spark.executor.result.size | The number of bytes this task transmitted back to the driver as the TaskResult. | long |
| apache_spark.executor.run_time | Elapsed time in the running this task | long |
| apache_spark.executor.shuffle.bytes_written | Number of bytes written in shuffle operations. | long |
| apache_spark.executor.shuffle.client.used.direct_memory | Amount of direct memory used by the shuffle client. | long |
| apache_spark.executor.shuffle.client.used.heap_memory | Amount of heap memory used by the shuffle client. | long |
| apache_spark.executor.shuffle.fetch_wait_time | Time the task spent waiting for remote shuffle blocks. | long |
| apache_spark.executor.shuffle.local.blocks_fetched | Number of local (as opposed to read from a remote executor) blocks fetched in shuffle operations. | long |
| apache_spark.executor.shuffle.local.bytes_read | Number of bytes read in shuffle operations from local disk (as opposed to read from a remote executor). | long |
| apache_spark.executor.shuffle.records.read | Number of records read in shuffle operations. | long |
| apache_spark.executor.shuffle.records.written | Number of records written in shuffle operations. | long |
| apache_spark.executor.shuffle.remote.blocks_fetched | Number of remote blocks fetched in shuffle operations. | long |
| apache_spark.executor.shuffle.remote.bytes_read | Number of remote bytes read in shuffle operations. | long |
| apache_spark.executor.shuffle.remote.bytes_read_to_disk | Number of remote bytes read to disk in shuffle operations. Large blocks are fetched to disk in shuffle read operations, as opposed to being read into memory, which is the default behavior. | long |
| apache_spark.executor.shuffle.server.used.direct_memory | Amount of direct memory used by the shuffle server. | long |
| apache_spark.executor.shuffle.server.used.heap_memory | Amount of heap memory used by the shuffle server. | long |
| apache_spark.executor.shuffle.total.bytes_read | Number of bytes read in shuffle operations (both local and remote) | long |
| apache_spark.executor.shuffle.write.time | Time spent blocking on writes to disk or buffer cache. The value is expressed in nanoseconds. | long |
| apache_spark.executor.succeeded_tasks | The number of tasks succeeded. | long |
| apache_spark.executor.threadpool.active_tasks | Number of tasks currently executing. | long |
| apache_spark.executor.threadpool.complete_tasks | Number of tasks that have completed in this executor. | long |
| apache_spark.executor.threadpool.current_pool_size | The size of the current thread pool of the executor. | long |
| apache_spark.executor.threadpool.max_pool_size | The maximum size of the thread pool of the executor. | long |
| apache_spark.executor.threadpool.started_tasks | The number of tasks started in the thread pool of the executor. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Node

This is the `node` data stream.

An example event for `node` looks as following:

```json
{
    "@timestamp": "2022-04-12T04:42:49.581Z",
    "agent": {
        "ephemeral_id": "ae57925e-eeca-4bf4-ae20-38f82db1378b",
        "id": "f051059f-86be-46d5-896d-ff1b2cdab179",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "apache_spark": {
        "node": {
            "main": {
                "applications": {
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
        "dataset": "apache_spark.node",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "f051059f-86be-46d5-896d-ff1b2cdab179",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.node",
        "duration": 8321835,
        "ingested": "2022-04-12T04:42:53Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.32.5"
        ],
        "mac": [
            "02:42:c0:a8:20:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-107-generic",
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
        "address": "http://apache-spark-main:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.node.main.applications.count | Total number of apps. | long |
| apache_spark.node.main.applications.waiting | Number of apps waiting. | long |
| apache_spark.node.main.workers.alive | Number of alive workers. | long |
| apache_spark.node.main.workers.count | Total number of workers. | long |
| apache_spark.node.worker.cores.free | Number of cores free. | long |
| apache_spark.node.worker.cores.used | Number of cores used. | long |
| apache_spark.node.worker.executors | Number of executors. | long |
| apache_spark.node.worker.memory.free | Number of cores free. | long |
| apache_spark.node.worker.memory.used | Amount of memory utilized in MB. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

