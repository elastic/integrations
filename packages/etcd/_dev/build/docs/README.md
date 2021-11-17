# etcd Integration

This integration periodically fetches metrics from [etcd](https://etcd.io/) servers. 

## Compatibility

The etcd `metrics` stream was tested with etcd 3.5.1.

## Metrics

### Metrics

The etcd `metrics` stream collects data from the etcd `metrics` module.

It's highly recommended to replace `127.0.0.1` with your server’s IP address and make sure that this page accessible to only you.

{{event "server"}}

{{fields "server"}}
