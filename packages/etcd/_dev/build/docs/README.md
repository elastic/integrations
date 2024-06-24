# etcd Integration

This integration is used to collect metrics from [etcd v2 and v3 instances](https://etcd.io/).

It periodically fetches metrics from [etcd metrics APIs](https://etcd.io/docs/v3.5/op-guide/monitoring/). 

## Data streams

For etcd v2, metrics are collected through the etcd v2 APIs, whereas for v3, they are fetched from the `/metrics` endpoint.

When using v3, datasets are bundled within `metrics` data stream, while for v2, available datasets include `leader`, `self`, and `store`.

etcd API endpoints:
- `/v2/stats/leader`: This endpoint provides metrics related to the current leadership status. Used by `leader` data stream.
- `/v2/stats/self`: Metrics exposed by this endpoint focus on the current node's status and performance. Used by `self` data stream.
- `/v2/stats/store`: This endpoint offers metrics related to the data storage layer, including data size, read/write operations, and storage efficiency. Used by `store` data stream.
- `/metrics` (v3 API): Unlike the more specific endpoints, this one provides a comprehensive set of metrics across various aspects of the system. Used by `metrics` data stream.

The etcd v2 APIs are not enabled by default. However, you can enable etcd v2 APIs when using etcd v3 and above by utilizing the `--enable-v2` flag, provided it is supported.

## Compatibility

The etcd package was tested with etcd `3.5.x`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from etcd, you must know the instance host.

Host Configuration Format: `http[s]://host:port`

Example Host Configuration: `http://localhost:2379`

## Metrics reference

### metrics

This is the `metrics` dataset of the etcd package, in charge of retrieving generic metrics from a etcd v3 instance.

{{event "metrics"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "metrics"}}

### leader

This is the `leader` dataset of the etcd package, in charge of retrieving generic metrics about leader from a etcd v2 instance.

{{event "leader"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "leader"}}

### self

This is the `self` dataset of the etcd package, in charge of retrieving generic metrics about self from a etcd v2 instance.

{{event "self"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "self"}}

### store

This is the `store` dataset of the etcd package, in charge of retrieving generic metrics about store from a etcd v2 instance.

{{event "store"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "store"}}