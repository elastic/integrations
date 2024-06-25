# CoreDNS Integration

This integration parses logs from [CoreDNS](https://coredns.io/) instances.

## Compatibility

This integration is designed to read CoreDNS logs running within a Kubernetes cluster or via systemd with logs output to journald. The CoreDNS datasets were tested with version 1.9.3 and 1.10.0.

## Logs

The log data stream expects logs from the CoreDNS [errors](https://coredns.io/plugins/errors/) plugin and the [log](https://coredns.io/plugins/log/) plugin. Query logs from the _log_ plugin can be in either the `common` or `combined` format (see [log format](https://coredns.io/plugins/log/#log-format) for details).
An example configuration with logging enabled is:
```
. {
  forward . 8.8.8.8
  errors
  log
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}

{{event "log"}}