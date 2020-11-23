# ZooKeeper Integration

This integration periodically fetches metrics from the [ZooKeeper](https://zookeeper.apache.org/) service.

## Compatibility

The ZooKeeper integration is tested with ZooKeeper 3.4.8 and is expected to work with all version >= 3.4.0. Versions prior to 3.4 do not support the mntr command.

## Metrics

### connection

The `connection` dataset fetches the data returned by the `cons` admin keyword.

{{event "connection"}}

{{fields "connection"}}

### mntr

The `mntr` Metricset fetches the data returned by the `mntr` admin keyword.

{{event "mntr"}}

{{fields "mntr"}}

### server

The `server` Metricset fetches the data returned by the `srvr` admin keyword.

{{event "server"}}

{{fields "server"}}
