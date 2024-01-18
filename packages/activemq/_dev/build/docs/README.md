# ActiveMQ Integration

This integration periodically fetches metrics from [ActiveMQ](https://activemq.apache.org/) servers. It can parse broker, queue and topic.
System logs and Audit logs are also collected using this integration.

## Compatibility

The ActiveMQ datasets were tested with ActiveMQ 5.17.1 or higher (independent from operating system).

## Troubleshooting

If host.ip is shown conflicted under ``log-*`` or ``metrics-*`` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Audit``, ``Log``, ``Broker``, ``Queue`` and ``Topic`` data stream's indices.

## Logs

### ActiveMQ Logs

Collects the ActiveMQ System logs.

{{event "log"}}

{{fields "log"}}

### Audit Logs

Audit logs collects the ActiveMQ Audit logs.

{{event "audit"}}

{{fields "audit"}}

## Metrics

### Broker Metrics

The server broker stream collects data from the ActiveMQ broker module. 

{{event "broker"}}

{{fields "broker"}}

### Queue Metrics

The server queue stream collects data from the ActiveMQ queue module.

{{event "queue"}}

{{fields "queue"}}

### Topic Metrics

The server topic stream collects data from the ActiveMQ topic module.

{{event "topic"}}

{{fields "topic"}}
