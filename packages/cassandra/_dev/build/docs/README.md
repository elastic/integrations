# Cassandra Integration

This integration periodically fetches metrics from [Cassandra](https://cassandra.apache.org/) using jolokia agent. It can parse System logs.

## Logs

Cassandra system logs from cassandra.log files.

{{event "log"}}

{{fields "log"}}

## Metrics

Cassandra metrics using jolokia agent installed on cassandra.

{{event "metrics"}}

{{fields "metrics"}}
