# Apache Spark Integration

The Apache Spark integration collects and parses data using the Jolokia Input.

## Compatibility

This integration has been tested against `Apache Spark version 3.5.0`

## Requirements

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

### Troubleshooting

If host.ip is shown conflicted under ``metrics-*`` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Application``, ``Driver``, ``Executor`` and ``Node`` data stream's indices.

## Metrics

### Application

This is the `application` data stream.

{{event "application"}}

{{fields "application"}}

### Driver

This is the `driver` data stream.

{{event "driver"}}

{{fields "driver"}}

### Executor

This is the `executor` data stream.

{{event "executor"}}

{{fields "executor"}}

### Node

This is the `node` data stream.

{{event "node"}}

{{fields "node"}}
