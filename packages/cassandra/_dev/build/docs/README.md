# Cassandra Integration

This integration periodically fetches metrics from [Cassandra](https://cassandra.apache.org/) using jolokia agent. It can parse System logs.

## Compatibility

This integration has been tested against `Cassandra version 3.11.11`.

## Steps to Setup Jolokia

### Prerequisites

- Java Development Kit (JDK) 1.8 or later
- Apache Cassandra 3.x/4.x (Adjust according to version)
- Jolokia agent

### Jolokia Setup

To monitor Cassandra with Jolokia, need to set up the Jolokia JVM agent.

1. Download the Jolokia JVM Agent:

   Obtain the latest Jolokia JVM agent `.jar` file from the [Jolokia official download page](https://repo1.maven.org/maven2/org/jolokia/jolokia-jvm/).

2. Place the Jolokia Agent:

   Copy the downloaded `.jar` file to a suitable location on the server where Cassandra is installed.

   For example:

   ```bash
   sudo cp jolokia-jvm-<version>-agent.jar /path/to/cassandra/lib/
   ```

3. Configure Cassandra to use the Jolokia Agent:

   To enable the Jolokia agent, modify the `cassandra-env.sh` by adding the following line at the bottom of file:

   ```
   JVM_OPTS="$JVM_OPTS -javaagent:/path/to/jolokia-jvm-<version>-agent.jar=port=7777,host=0.0.0.0"
   ```

4. Restart Cassandra:

   After configuring Cassandra with the Jolokia agent, restart the Cassandra service to apply the changes.

   Note:
   - Restarting the Cassandra service will temporarily disrupt database connectivity. Dependent services may experience failures and should be designed to handle such interruptions gracefully.
   - Immediately after a restart, Cassandra's performance may be impacted due to cold caches and commit log replay.
   - Ensure no cluster maintenance tasks are in progress during the restart to prevent any unintended consequences.

## Troubleshooting

- If `log.flags` appears conflicted under the ``logs-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Logs`` data stream.

## Logs

Cassandra system logs from cassandra.log files.

{{event "log"}}

{{fields "log"}}

## Metrics

Cassandra metrics using jolokia agent installed on cassandra.

{{event "metrics"}}

{{fields "metrics"}}
