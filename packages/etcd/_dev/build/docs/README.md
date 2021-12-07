# etcd Integration

This integration is used to collect metrics from [etcd v2 and v3 servers](https://etcd.io/).
This integration periodically fetches metrics from [etcd monitoring server APIs](https://etcd.io/docs/v3.1/op-guide/monitoring/). 

## Compatibility

The etcd package was tested with etcd 3.5.1.

## Metrics

When using etcd v2, metrics are collected using etcd v2 API. When using v3, metrics are retrieved from the /metrics endpoint.

When using v3, datasets are bundled into `metrics`. When using v2, datasets available are `leader`, `self` and `store`.

### metrics

This is the `metrics` dataset of the etcd package, in charge of retrieving generic metrics from a etcd v3 instance.

{{event "metrics"}}

{{fields "metrics"}}

### leader

This is the `leader` dataset of the etcd package, in charge of retrieving generic metrics about leader from a etcd v2 instance.

{{event "leader"}}

{{fields "leader"}}

### self

This is the `self` dataset of the etcd package, in charge of retrieving generic metrics about self from a etcd v2 instance.

{{event "self"}}

{{fields "self"}}

### store

This is the `store` dataset of the etcd package, in charge of retrieving generic metrics about store from a etcd v2 instance.

{{event "store"}}

{{fields "store"}}