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

{{event "log"}}

{{fields "log"}}

## Metrics

Cassandra metrics using jolokia agent installed on cassandra.

{{event "metrics"}}

{{fields "metrics"}}
