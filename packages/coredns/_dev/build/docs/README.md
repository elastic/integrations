# CoreDNS Integration

This integration parses logs from [CoreDNS](https://coredns.io/) instances.

## Compatibility

This integration is designed to read CoreDNS logs running within a Kubernetes cluster or via systemd with logs output to Journald. The CoreDNS datasets were tested with version 1.9.3.

## Logs

CoreDNS Query and Error logs.  The integration expects Query logs using the `common` or `combined` Log format explain [here](https://coredns.io/plugins/log/#log-format)

{{fields "log"}}
