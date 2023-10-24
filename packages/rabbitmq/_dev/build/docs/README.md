# RabbitMQ Integration

This integration uses [HTTP API](http://www.rabbitmq.com/management.html) created by the management plugin to collect metrics.

The default data streams are `connection`, `node`, `queue`, `exchange` and standard logs.

If `management.path_prefix` is set in RabbitMQ configuration, management_path_prefix has to be set to the same value
in this integration configuration.

## Compatibility

The RabbitMQ integration is fully tested with RabbitMQ 3.7.4 and it should be compatible with any version supporting
the management plugin (which needs to be installed and enabled). Exchange dataset is also tested with 3.6.0, 3.6.5 and 3.7.14.

The application logs dataset parses single file format introduced in 3.7.0.

## Logs

### Application Logs

Application logs collects standard RabbitMQ logs.
It will only support RabbitMQ default i.e RFC 3339 timestamp format.

{{fields "log"}}

## Metrics

### Connection Metrics

{{event "connection"}}

{{fields "connection"}}

### Exchange Metrics

{{event "exchange"}}

{{fields "exchange"}}

### Node Metrics

The "node" dataset collects metrics about RabbitMQ nodes.

It supports two modes to collect data which can be selected with the "Collection mode" setting:

* `node` - collects metrics only from the node the agent connects to.
* `cluster` - collects metrics from all the nodes in the cluster. This is recommended when collecting metrics of an only endpoint for the whole cluster.

{{event "node"}}

{{fields "node"}}

### Queue Metrics

{{event "queue"}}

{{fields "queue"}}