# Cassandra Integration

This integration periodically fetches metrics from [Cassandra](https://cassandra.apache.org/) using jolokia agent. It can parse System logs.

## Compatibility

This integration has been tested against `Cassandra version 3.11.11`.

### Troubleshooting

If log.flags is shown conflicted under the ``logs-*`` data view, then this issue can be solved by reindexing the ``Logs`` data stream's indices.

Note:
- This [document](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) provides details about reindexing.

## Logs

Cassandra system logs from cassandra.log files.

{{event "log"}}

{{fields "log"}}

## Metrics

Cassandra metrics using jolokia agent installed on cassandra.

{{event "metrics"}}

{{fields "metrics"}}
