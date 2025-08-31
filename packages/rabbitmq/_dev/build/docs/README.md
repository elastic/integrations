# RabbitMQ Integration

This integration uses [HTTP API](http://www.rabbitmq.com/management.html) created by the management plugin to collect metrics.

The default data streams are `connection`, `node`, `queue`, `exchange` and standard logs.

If `management.path_prefix` is set in RabbitMQ configuration, management_path_prefix has to be set to the same value
in this integration configuration.

## Compatibility

The RabbitMQ integration is fully tested with RabbitMQ 3.7.4 and 4.1.3, and it should be compatible with any version supporting the management plugin (which needs to be installed and enabled). It has also been tested with 3.6.0, 3.6.5, and 3.7.14.

The application logs dataset parses single file format introduced in 3.7.0.

When upgrading RabbitMQ to version 4.1.3 or above, the `/api/nodes` endpoint no longer returns the `rabbitmq.node.queue.index.journal_write` metric in its response. This metric is used in the Kibana dashboard "Queue Index Operations [Metrics RabbitMQ]". As a result, after upgrading to 4.1.3 or later, this metric and related visualizations in the dashboard will be missing or incomplete.

## Logs

### Application Logs

Application logs collects standard RabbitMQ logs.
It will only support RabbitMQ default i.e RFC 3339 timestamp format.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}

## Metrics

### Connection Metrics

{{event "connection"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "connection"}}

### Exchange Metrics

{{event "exchange"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "exchange"}}

### Node Metrics

The "node" dataset collects metrics about RabbitMQ nodes.

It supports two modes to collect data which can be selected with the "Collection mode" setting:

* `node` - collects metrics only from the node the agent connects to.
* `cluster` - collects metrics from all the nodes in the cluster. This is recommended when collecting metrics of an only endpoint for the whole cluster.

{{event "node"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "node"}}

### Queue Metrics

{{event "queue"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "queue"}}