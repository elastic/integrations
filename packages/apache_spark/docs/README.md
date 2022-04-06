# Apache Spark Integration

The Apache Spark integration collects and parses data using the Jolokia Metricbeat Module.

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

### Executors

This is the `executors` data stream.

An example event for `executors` looks as following:

```json
{
    "@timestamp": "2022-04-06T08:08:28.124Z",
    "agent": {
        "ephemeral_id": "7fce3dcb-c11a-4198-9857-ad44c74fa030",
        "id": "af0205ec-949f-45d9-b3bf-b41d93032a55",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "apache_spark": {
        "executors": {
            "application_name": "app-20220406080805-0000",
            "id": "0",
            "process_tree": {
                "python": {
                    "rss_memory": 0
                }
            }
        }
    },
    "data_stream": {
        "dataset": "apache_spark.executors",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "af0205ec-949f-45d9-b3bf-b41d93032a55",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.executors",
        "duration": 30066789,
        "ingested": "2022-04-06T08:08:31Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
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
        "address": "http://apache-spark-main:7780/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_spark.executors.application_name | Name of application. | keyword |
| apache_spark.executors.bytes.read | Total number of bytes read. | long |
| apache_spark.executors.bytes.written | Total number of bytes written. | long |
| apache_spark.executors.disk_bytes_spilled | Total number of disk bytes spilled. | long |
| apache_spark.executors.file_cache_hits | Total number of file cache hits. | long |
| apache_spark.executors.files_discovered | Total number of files discovered. | long |
| apache_spark.executors.filesystem.file.large_read_ops | Total number of large read operations from the files. | long |
| apache_spark.executors.filesystem.file.read_bytes | Total number of bytes read from the files. | long |
| apache_spark.executors.filesystem.file.read_ops | Total number of read operations from the files. | long |
| apache_spark.executors.filesystem.file.write_bytes | Total number of bytes written from the files. | long |
| apache_spark.executors.filesystem.file.write_ops | Total number of write operations from the files. | long |
| apache_spark.executors.filesystem.hdfs.large_read_ops | Total number of large read operations from HDFS. | long |
| apache_spark.executors.filesystem.hdfs.read_bytes | Total number of read bytes from HDFS. | long |
| apache_spark.executors.filesystem.hdfs.read_ops | Total number of read operations from HDFS. | long |
| apache_spark.executors.filesystem.hdfs.write_bytes | Total number of write bytes from HDFS. | long |
| apache_spark.executors.filesystem.hdfs.write_ops | Total number of write operations from HDFS. | long |
| apache_spark.executors.gc.major.count | Total major GC count. For example, the garbage collector is one of MarkSweepCompact, PS MarkSweep, ConcurrentMarkSweep, G1 Old Generation and so on. | long |
| apache_spark.executors.gc.major.time | Elapsed total major GC time. The value is expressed in milliseconds. | long |
| apache_spark.executors.gc.minor.count | Total minor GC count. For example, the garbage collector is one of Copy, PS Scavenge, ParNew, G1 Young Generation and so on. | long |
| apache_spark.executors.gc.minor.time | Elapsed total minor GC time. The value is expressed in milliseconds. | long |
| apache_spark.executors.generated_class_size | Size of the class generated. | long |
| apache_spark.executors.generated_method_size | Size of the method generated. | long |
| apache_spark.executors.heap_memory.off.execution | Peak off heap execution memory in use, in bytes. | long |
| apache_spark.executors.heap_memory.off.storage | Peak off heap storage memory in use, in bytes. | long |
| apache_spark.executors.heap_memory.off.unified | Peak off heap memory (execution and storage). | long |
| apache_spark.executors.heap_memory.on.execution | Peak on heap execution memory in use, in bytes. | long |
| apache_spark.executors.heap_memory.on.storage | Peak on heap storage memory in use, in bytes. | long |
| apache_spark.executors.heap_memory.on.unified | Peak on heap memory (execution and storage). | long |
| apache_spark.executors.hive_client_calls | Total number of Hive Client calls. | long |
| apache_spark.executors.id | ID of executor. | keyword |
| apache_spark.executors.jvm.cpu_time | Elapsed CPU time the JVM spent. | long |
| apache_spark.executors.jvm.gc_time | Elapsed time the JVM spent in garbage collection while executing this task. | long |
| apache_spark.executors.memory.direct_pool | Peak memory that the JVM is using for direct buffer pool. | long |
| apache_spark.executors.memory.jvm.heap | Peak memory usage of the heap that is used for object allocation. | long |
| apache_spark.executors.memory.jvm.off_heap | Peak memory usage of non-heap memory that is used by the Java virtual machine. | long |
| apache_spark.executors.memory.mapped_pool | Peak memory that the JVM is using for mapped buffer pool | long |
| apache_spark.executors.memory_bytes_spilled | The number of in-memory bytes spilled by this task. | long |
| apache_spark.executors.parallel_listing_job_count | Number of jobs running parallely. | long |
| apache_spark.executors.partitions_fetched | Number of partitions fetched. | long |
| apache_spark.executors.process_tree.jvm.rss_memory | Resident Set Size: number of pages the process has in real memory. This is just the pages which count toward text, data, or stack space. This does not include pages which have not been demand-loaded in, or which are swapped out. | long |
| apache_spark.executors.process_tree.jvm.v_memory | Virtual memory size in bytes. | long |
| apache_spark.executors.process_tree.other.rss_memory | Resident Set Size for other kind of process. | long |
| apache_spark.executors.process_tree.other.v_memory | Virtual memory size for other kind of process in bytes. | long |
| apache_spark.executors.process_tree.python.rss_memory | Resident Set Size for Python. | long |
| apache_spark.executors.process_tree.python.v_memory | Virtual memory size for Python in bytes. | long |
| apache_spark.executors.records.read | Total number of records read. | long |
| apache_spark.executors.records.written | Total number of records written. | long |
| apache_spark.executors.result.serialization_time | Elapsed time spent serializing the task result. The value is expressed in milliseconds. | long |
| apache_spark.executors.result.size | The number of bytes this task transmitted back to the driver as the TaskResult. | long |
| apache_spark.executors.run_time | Elapsed time in the running this task | long |
| apache_spark.executors.shuffle.bytes_written | Number of bytes written in shuffle operations. | long |
| apache_spark.executors.shuffle.client.used.direct_memory | Amount of direct memory used by the shuffle client. | long |
| apache_spark.executors.shuffle.client.used.heap_memory | Amount of heap memory used by the shuffle client. | long |
| apache_spark.executors.shuffle.fetch_wait_time | Time the task spent waiting for remote shuffle blocks. | long |
| apache_spark.executors.shuffle.local.blocks_fetched | Number of local (as opposed to read from a remote executor) blocks fetched in shuffle operations. | long |
| apache_spark.executors.shuffle.local.bytes_read | Number of bytes read in shuffle operations from local disk (as opposed to read from a remote executor). | long |
| apache_spark.executors.shuffle.records.read | Number of records read in shuffle operations. | long |
| apache_spark.executors.shuffle.records.written | Number of records written in shuffle operations. | long |
| apache_spark.executors.shuffle.remote.blocks_fetched | Number of remote blocks fetched in shuffle operations. | long |
| apache_spark.executors.shuffle.remote.bytes_read | Number of remote bytes read in shuffle operations. | long |
| apache_spark.executors.shuffle.remote.bytes_read_to_disk | Number of remote bytes read to disk in shuffle operations. Large blocks are fetched to disk in shuffle read operations, as opposed to being read into memory, which is the default behavior. | long |
| apache_spark.executors.shuffle.server.used.direct_memory | Amount of direct memory used by the shuffle server. | long |
| apache_spark.executors.shuffle.server.used.heap_memory | Amount of heap memory used by the shuffle server. | long |
| apache_spark.executors.shuffle.total.bytes_read | Number of bytes read in shuffle operations (both local and remote) | long |
| apache_spark.executors.shuffle.write.time | Time spent blocking on writes to disk or buffer cache. The value is expressed in nanoseconds. | long |
| apache_spark.executors.source_code_size | The total size of the source code. | long |
| apache_spark.executors.succeeded_tasks | The number of tasks succeeded. | long |
| apache_spark.executors.threadpool.active_tasks | Number of tasks currently executing. | long |
| apache_spark.executors.threadpool.complete_tasks | Number of tasks that have completed in this executor. | long |
| apache_spark.executors.threadpool.current_pool_size | The size of the current thread pool of the executor. | long |
| apache_spark.executors.threadpool.max_pool_size | The maximum size of the thread pool of the executor. | long |
| apache_spark.executors.threadpool.started_tasks | The number of tasks started in the thread pool of the executor. | long |
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

This is the `nodes` data stream.

An example event for `nodes` looks as following:

```json
{
    "@timestamp": "2022-04-04T10:53:20.597Z",
    "agent": {
        "ephemeral_id": "1a8a01d7-f619-4c9c-8528-af2b6792d9c0",
        "id": "4e4e07c4-a787-4988-a436-5c373d54738a",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "apache_spark": {
        "nodes": {
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
        "dataset": "apache_spark.nodes",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "4e4e07c4-a787-4988-a436-5c373d54738a",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache_spark.nodes",
        "duration": 6157145,
        "ingested": "2022-04-04T10:53:24Z",
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.64.7"
        ],
        "mac": [
            "02:42:c0:a8:40:07"
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
    "jolokia": {},
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
| apache_spark.nodes.main.applications.count | Total number of apps. | long |
| apache_spark.nodes.main.applications.waiting | Number of apps waiting. | long |
| apache_spark.nodes.main.workers.alive | Number of alive workers. | long |
| apache_spark.nodes.main.workers.count | Total number of workers. | long |
| apache_spark.nodes.worker.cores.free | Number of cores free. | long |
| apache_spark.nodes.worker.cores.used | Number of cores used. | long |
| apache_spark.nodes.worker.executors | Number of executors. | long |
| apache_spark.nodes.worker.memory.free | Number of cores free. | long |
| apache_spark.nodes.worker.memory.used | Amount of memory utilized in MB. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

