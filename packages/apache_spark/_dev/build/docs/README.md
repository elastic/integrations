# Apache Spark Integration

## Overview

[Apache Spark](https://spark.apache.org) is an open-source, distributed computing system that provides a fast and general-purpose cluster-computing framework. It offers in-memory data processing capabilities, which significantly enhances the performance of big data analytics applications. Spark provides support for a variety of programming languages including Scala, Python, Java, and R, and comes with built-in modules for SQL, streaming, machine learning, and graph processing. This makes it a versatile tool for a wide range of data processing and analysis tasks.

Use the Apache Spark integration to:

- Collect metrics related to the application, driver, executor and node.
- Create visualizations to monitor, measure, and analyze usage trends and key data, deriving business insights.
- Create alerts to reduce the MTTD and MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Apache Spark integration collects metrics data.

Metrics provide insight into the statistics of Apache Spark. The `Metric` data streams collected by the Apache Spark integration include `application`, `driver`, `executor`, and `node`, allowing users to monitor and troubleshoot the performance of their Apache Spark instance.

Data streams:
- `application`: Collects information related to the number of cores used, application name, runtime in milliseconds and current status of the application.
- `driver`: Collects information related to the driver details, job durations, task execution, memory usage, executor status and JVM metrics.
- `executor`: Collects information related to the operations, memory usage, garbage collection, file handling, and threadpool activity.
- `node`: Collects information related to the application count, waiting applications, worker metrics, executor count, core usage and memory usage.

Note:
- Users can monitor and view the metrics inside the ingested documents for Apache Spark under the `metrics-*` index pattern in `Discover`.

## Compatibility

This integration has been tested against `Apache Spark version 3.5.0`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Apache Spark, you must know the full hosts for the Main and Worker nodes.

To proceed with the Jolokia setup, Apache Spark should be installed as a standalone setup. Make sure that the spark folder is installed in the `/usr/local` path. If not, then specify the path of spark folder in the further steps. You can install the standalone setup from the official download page of [Apache Spark](https://spark.apache.org/downloads.html).

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

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting Started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Validation

After the integration is successfully configured, click on the *Assets* tab of the Apache Spark Integration to display the available dashboards. Select the dashboard for your configured data stream, which should be populated with the required data.

## Troubleshooting

If `host.ip` appears conflicted under the ``metrics-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds-reindex.html) the ``Application``, ``Driver``, ``Executor`` and ``Node`` data stream.

## Metrics

### Application

The `application` data stream collects metrics related to the number of cores used, application name, runtime in milliseconds, and current status of the application.

{{event "application"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "application"}}

### Driver

The `driver` data stream collects metrics related to the driver details, job durations, task execution, memory usage, executor status, and JVM metrics.

{{event "driver"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "driver"}}

### Executor

The `executor` data stream collects metrics related to the operations, memory usage, garbage collection, file handling, and threadpool activity.

{{event "executor"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "executor"}}

### Node

The `node` data stream collects metrics related to the application count, waiting applications, worker metrics, executor count, core usage, and memory usage.

{{event "node"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "node"}}
