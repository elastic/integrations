# etcd Integration

This integration is used to collect metrics from [etcd v2 and v3 instances](https://etcd.io/).

It periodically fetches metrics from [etcd metrics APIs](https://etcd.io/docs/v3.1/op-guide/monitoring/). 

## Compatibility

The etcd package was tested with etcd `3.5.x`.

## Metrics

For etcd v2, metrics are collected through the etcd v2 APIs, whereas for v3, they are fetched from the `/metrics` endpoint.

When using v3, datasets are bundled within `metrics` data stream, while for v2, available datasets include `leader`, `self`, and `store`.

The etcd v2 APIs are not enabled by default. However, you can enable etcd v2 APIs when using etcd v3 and above by utilizing the --enable-v2 flag, provided it is supported.


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