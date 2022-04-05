# Apache Spark

The Apache Spark integration collects and parses data using the Jolokia Metricbeat Module.

## Compatibility

<<<<<<< HEAD
This module has been tested against `Apache Spark version 3.2.0`
=======
This integration has been tested against `Apache Spark version 3.2.0`
>>>>>>> acfb43c556154ae398e89ab340c67999079cd425

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
<<<<<<< HEAD
        "dataset": "apache_spark.metrics",
=======
        "dataset": "apache_spark.nodes",
>>>>>>> acfb43c556154ae398e89ab340c67999079cd425
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
<<<<<<< HEAD
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
=======
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
>>>>>>> acfb43c556154ae398e89ab340c67999079cd425
        "kind": "metric",
        "module": "apache_spark",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
<<<<<<< HEAD
            "172.21.0.5"
        ],
        "mac": [
            "02:42:ac:15:00:05"
=======
            "192.168.64.7"
        ],
        "mac": [
            "02:42:c0:a8:40:07"
>>>>>>> acfb43c556154ae398e89ab340c67999079cd425
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
<<<<<<< HEAD
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
=======
            "kernel": "5.4.0-100-generic",
>>>>>>> acfb43c556154ae398e89ab340c67999079cd425
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
<<<<<<< HEAD
=======
    "jolokia": {},
>>>>>>> acfb43c556154ae398e89ab340c67999079cd425
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
<<<<<<< HEAD
        "address": "http://apachesparkmaster:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
=======
        "address": "http://apache-spark-main:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
>>>>>>> acfb43c556154ae398e89ab340c67999079cd425
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
<<<<<<< HEAD
| apache_spark.metrics.driver.application_name |  | keyword |
| apache_spark.metrics.driver.dag_scheduler.job.active |  | long |
| apache_spark.metrics.driver.dag_scheduler.job.all |  | long |
| apache_spark.metrics.driver.dag_scheduler.stages.failed |  | long |
| apache_spark.metrics.driver.dag_scheduler.stages.running |  | long |
| apache_spark.metrics.driver.dag_scheduler.stages.waiting |  | long |
| apache_spark.metrics.driver.disk.space_used |  | long |
| apache_spark.metrics.driver.executor_metrics.gc.major.count |  | long |
| apache_spark.metrics.driver.executor_metrics.gc.major.time |  | long |
| apache_spark.metrics.driver.executor_metrics.gc.minor.count |  | long |
| apache_spark.metrics.driver.executor_metrics.gc.minor.time |  | long |
| apache_spark.metrics.driver.executor_metrics.heap_memory.off.execution |  | long |
| apache_spark.metrics.driver.executor_metrics.heap_memory.off.storage |  | long |
| apache_spark.metrics.driver.executor_metrics.heap_memory.off.unified |  | long |
| apache_spark.metrics.driver.executor_metrics.heap_memory.on.execution |  | long |
| apache_spark.metrics.driver.executor_metrics.heap_memory.on.storage |  | long |
| apache_spark.metrics.driver.executor_metrics.heap_memory.on.unified |  | long |
| apache_spark.metrics.driver.executor_metrics.memory.direct_pool |  | long |
| apache_spark.metrics.driver.executor_metrics.memory.jvm.heap |  | long |
| apache_spark.metrics.driver.executor_metrics.memory.jvm.off_heap |  | long |
| apache_spark.metrics.driver.executor_metrics.memory.mapped_pool |  | long |
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
=======
| apache_spark.nodes.main.applications.count | Total number of apps. | long |
| apache_spark.nodes.main.applications.waiting | Number of apps waiting. | long |
| apache_spark.nodes.main.workers.alive | Number of alive workers. | long |
| apache_spark.nodes.main.workers.count | Total number of workers. | long |
| apache_spark.nodes.worker.cores.free | Number of cores free. | long |
| apache_spark.nodes.worker.cores.used | Number of cores used. | long |
| apache_spark.nodes.worker.executors | Number of executors. | long |
| apache_spark.nodes.worker.memory.free | Number of cores free. | long |
| apache_spark.nodes.worker.memory.used | Amount of memory utilized in MB. | long |
>>>>>>> acfb43c556154ae398e89ab340c67999079cd425
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

