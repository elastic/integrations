# Etcd Integration

This integration is used to collect metrics from [Etcd v2 and v3 servers](https://etcd.io/).
This integration periodically fetches metrics from [etcd monitoring server APIs](https://etcd.io/docs/v3.1/op-guide/monitoring/). 

## Compatibility

The Etcd package was tested with Etcd 3.5.1.

## Metrics

When using V2, metrics are collected using Etcd v2 API. When using V3, metrics are retrieved from the /metrics endpoint as intended for Etcd v3.

When using V3, metricsest are bundled into `metrics`. When using V2, metricsets available are `leader`, `self` and `store`.

### metrics

This is the `metrics` endpoint metricset of the etcd module. This metrics is being read from the Etcd V3 endpoint and won’t show any activity regarding Etcd V2.

{{event "metrics"}}

{{fields "metrics"}}

### leader

This is the `leader` metricset of the module etcd. This metrics is being read from the Etcd V2 endpoint and won’t show any activity regarding Etcd V3.

{{event "leader"}}

{{fields "leader"}}

### self

This is the `self` metricset of the module etcd. This metrics is being read from the Etcd V2 endpoint and won’t show any activity regarding Etcd V3.

{{event "self"}}

{{fields "self"}}

### store

This is the `store` metricset of the module etcd. This metrics is being read from the Etcd V2 endpoint and won’t show any activity regarding Etcd V3.

{{event "store"}}

{{fields "store"}}