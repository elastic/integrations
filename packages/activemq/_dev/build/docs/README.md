# ActiveMQ Integration

This integration periodically fetches metrics from [ActiveMQ](https://activemq.apache.org/) servers. It can parse broker, queue and topic.
logs created by the ActiveMQ server - system logs and audit logs.

## Compatibility

The ActiveMQ datasets were tested with ActiveMQ 5.15.9 or higher (independent from operating system).

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
