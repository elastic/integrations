# Cassandra Integration

This integration periodically fetches metrics from [Cassandra](https://cassandra.apache.org/) using jolokia agent. It can parse System logs.

## Compatibility

This integration has been tested against `Cassandra version 3.11.11`.

## Logs

Cassandra system logs from cassandra.log files.

{{event "log"}}

{{fields "log"}}

## Metrics

Cassandra metrics using jolokia agent installed on cassandra.

{{event "metrics"}}

{{fields "metrics"}}
