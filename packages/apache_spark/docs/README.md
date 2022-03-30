# Apache Spark

The Apache Spark integration collects and parses data using the Jolokia Metricbeat Module.

## Compatibility

This module has been tested against `Apache Spark version 3.2.0`

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
            "executors": {
                "application_name": "app-20220322011157-0169",
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
| apache_spark.metrics.executors.application_name |  | keyword |
| apache_spark.metrics.executors.bytes.read |  | long |
| apache_spark.metrics.executors.bytes.written |  | long |
| apache_spark.metrics.executors.compilation_time |  | long |
| apache_spark.metrics.executors.cpu_time |  | long |
| apache_spark.metrics.executors.deserialize.cpu_time |  | long |
| apache_spark.metrics.executors.deserialize.time |  | long |
| apache_spark.metrics.executors.direct_pool_memory |  | long |
| apache_spark.metrics.executors.disk_bytes_spilled |  | long |
| apache_spark.metrics.executors.file_cache_hits |  | long |
| apache_spark.metrics.executors.files_discovered |  | long |
| apache_spark.metrics.executors.filesystem.file.large_read_ops |  | long |
| apache_spark.metrics.executors.filesystem.file.read_bytes |  | long |
| apache_spark.metrics.executors.filesystem.file.read_ops |  | long |
| apache_spark.metrics.executors.filesystem.file.write_bytes |  | long |
| apache_spark.metrics.executors.filesystem.file.write_ops |  | long |
| apache_spark.metrics.executors.filesystem.hdfs.large_read_ops |  | long |
| apache_spark.metrics.executors.filesystem.hdfs.read_bytes |  | long |
| apache_spark.metrics.executors.filesystem.hdfs.read_ops |  | long |
| apache_spark.metrics.executors.filesystem.hdfs.write_bytes |  | long |
| apache_spark.metrics.executors.filesystem.hdfs.write_ops |  | long |
| apache_spark.metrics.executors.generated_class_size |  | long |
| apache_spark.metrics.executors.generated_method_size |  | long |
| apache_spark.metrics.executors.hive_client_calls |  | long |
| apache_spark.metrics.executors.id |  | keyword |
| apache_spark.metrics.executors.jvm.cpu_time |  | long |
| apache_spark.metrics.executors.jvm.gc_time |  | long |
| apache_spark.metrics.executors.jvm.heap_memory |  | long |
| apache_spark.metrics.executors.jvm.off_heap_memory |  | long |
| apache_spark.metrics.executors.major_gc.count |  | long |
| apache_spark.metrics.executors.major_gc.time |  | long |
| apache_spark.metrics.executors.mapped_pool_memory |  | long |
| apache_spark.metrics.executors.memory_bytes_spilled |  | long |
| apache_spark.metrics.executors.minor_gc.count |  | long |
| apache_spark.metrics.executors.minor_gc.time |  | long |
| apache_spark.metrics.executors.shuffle.bytes_written |  | long |
| apache_spark.metrics.executors.shuffle.client.used.direct_memory |  | long |
| apache_spark.metrics.executors.shuffle.client.used.heap_memory |  | long |
| apache_spark.metrics.executors.shuffle.fetch_wait_time |  | long |
| apache_spark.metrics.executors.shuffle.local.blocks_fetched |  | long |
| apache_spark.metrics.executors.shuffle.local.bytes_read |  | long |
| apache_spark.metrics.executors.shuffle.records.read |  | long |
| apache_spark.metrics.executors.shuffle.records.written |  | long |
| apache_spark.metrics.executors.shuffle.remote.blocks_fetched |  | long |
| apache_spark.metrics.executors.shuffle.remote.bytes_read |  | long |
| apache_spark.metrics.executors.shuffle.remote.bytes_read_to_disk |  | long |
| apache_spark.metrics.executors.shuffle.server.used.direct_memory |  | long |
| apache_spark.metrics.executors.shuffle.server.used.heap_memory |  | long |
| apache_spark.metrics.executors.shuffle.total.bytes_read |  | long |
| apache_spark.metrics.executors.shuffle.write.time |  | long |
| apache_spark.metrics.executors.source_code_size |  | long |
| apache_spark.metrics.executors.succeeded_tasks |  | long |
| apache_spark.metrics.executors.threadpool.active_tasks |  | long |
| apache_spark.metrics.executors.threadpool.complete_tasks |  | long |
| apache_spark.metrics.executors.threadpool.current_pool_size |  | long |
| apache_spark.metrics.executors.threadpool.max_pool_size |  | long |
| apache_spark.metrics.executors.threadpool.started_tasks |  | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

