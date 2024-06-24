# ZooKeeper Integration

This integration periodically fetches metrics from the [ZooKeeper](https://zookeeper.apache.org/) service.

## Compatibility

The ZooKeeper integration is tested with ZooKeeper 3.4.8 and is expected to work with all version >= 3.4.0. Versions prior to 3.4 do not support the mntr command.

## Metrics

### connection

The `connection` dataset fetches the data returned by the `cons` admin keyword.

{{event "connection"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "connection"}}

### mntr

The `mntr` Metricset fetches the data returned by the `mntr` admin keyword.

{{event "mntr"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "mntr"}}

### server

The `server` Metricset fetches the data returned by the `srvr` admin keyword.

{{event "server"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "server"}}
