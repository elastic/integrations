# Couchbase Integration

This Elastic integration collects and parses the [Bucket](https://docs.couchbase.com/server/current/rest-api/rest-buckets-summary.html), [Cluster](https://docs.couchbase.com/server/current/rest-api/rest-cluster-details.html), and [Couchbase Lite Replication](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#cbl_replication_pull) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses:
- `http` metricbeat module to collect `bucket`, and `cluster` metrics.
- `prometheus` metricbeat module to collect `cbl_replication` metrics.

Note: For Couchbase cluster setup, there is an ideal scenario of single host with administrator access for the entire cluster to collect metrics. Providing multiple host from the same cluster might lead to data duplication. In case of multiple clusters, adding a new integration to collect data from different cluster host is a good option.

## Compatibility

This integration has been tested against Couchbase `v6.6`, `v7.0` and `v7.1`.

## Requirements

In order to ingest data from Couchbase, you must know the host(s) and the administrator credentials for the Couchbase instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://Administrator:password@localhost:8091`

In order to collect data using [Sync Gateway](https://www.couchbase.com/products/sync-gateway), follow the steps given below:
- Download and configure [Sync Gateway](https://docs.couchbase.com/sync-gateway/current/get-started-install.html)
- Download and configure [Sync Gateway Promethus Exporter](https://github.com/couchbaselabs/couchbase-sync-gateway-exporter.git) and provide Sync Gateway Host using --sgw.url flag while running the Exporter App
- Example configuration: `--sgw.url=http://sgw:4985`

## Metrics

### Bucket

This is the `bucket` data stream. A bucket is a logical container for a related set of items such as key-value pairs or documents.

{{event "bucket"}}

{{fields "bucket"}}

### Cluster

This is the `cluster` data stream. A cluster is a collection of nodes that are accessed and managed as a single group. Each node is an equal partner in orchestrating the cluster to provide facilities such as operational information (monitoring) or managing cluster membership of nodes and health of nodes.

{{event "cluster"}}

{{fields "cluster"}}

### Couchbase Lite Replication

This is the `cbl_replication` data stream.

CBL Replication push is a process by which clients upload database changes from the local source database to the remote (server) target database.

CBL Replication pull is a process by which clients download database changes from the remote (server) source database to the local target database.

{{event "cbl_replication"}}

{{fields "cbl_replication"}}
