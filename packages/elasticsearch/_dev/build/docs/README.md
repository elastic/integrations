# Elasticsearch

The `elasticsearch` package collects metrics and logs of Elasticsearch.

## Compatibility

The `elasticsearch` package can monitor Elasticsearch 8.5.0 and later.

## Logs

NOTE: Configure the `var.paths` setting to point to JSON logs.

### Audit

{{fields "audit"}}

### Deprecation

{{fields "deprecation"}}

### Garbage collection

{{fields "gc"}}

### Server

{{fields "server"}}

### Slowlog

{{fields "slowlog"}}

## Metrics

### Usage for Stack Monitoring

The `elasticsearch` package can be used to collect logs and metrics shown in our Stack Monitoring
UI in Kibana.

### Metric-specific configuration notes

Like other package, `elasticsearch` metrics collection accepts a `hosts` configuration setting.
This setting can contain a list of entries. The related `scope` setting determines how each entry in
the `hosts` list is interpreted by the module.

* If `scope` is set to `node` (default), each entry in the `hosts` list indicates a distinct node in an
  Elasticsearch cluster.
* If `scope` is set to `cluster`, each entry in the `hosts` list indicates a single endpoint for a distinct
  Elasticsearch cluster (for example, a load-balancing proxy fronting the cluster).

### Cross Cluster Replication

CCR It uses the Cross-Cluster Replication Stats API endpoint to fetch metrics about cross-cluster
replication from the Elasticsearch clusters that are participating in cross-cluster
replication.

If the Elasticsearch cluster does not have cross-cluster replication enabled, this package
will not collect metrics. A DEBUG log message about this will be emitted in the log.

{{fields "ccr"}}

### Cluster Stats

`cluster_stats` interrogates the 
{{ url "elasticsearch-cluster-stats" "Cluster Stats API endpoint" }}
to fetch information about the Elasticsearch cluster.

{{event "cluster_stats"}}

{{fields "cluster_stats"}}

### Enrich

Enrch interrogates the {{ url "elasticsearch-enrich-stats-api" "Enrich Stats API" }}
endpoint to fetch information about Enrich coordinator nodesin the Elasticsearch cluster that are participating in 
ingest-time enrichment.

{{event "enrich"}}

{{fields "enrich"}}

### Index

{{event "index"}}

{{fields "index"}}

### Index recovery

By default only data about indices which are under active recovery are fetched.
To gather data about all indices set `active_only: false`.

{{event "index_recovery"}}

{{fields "index_recovery"}}


### Index summary

{{event "index_summary"}}

{{fields "index_summary"}}

### Machine Learning Jobs

If you have Machine Learning jobs, this data stream will interrogate the 
{{ url "elasticsearch-ml-apis" "Machine Learning Anomaly Detection API" }}
and  requires [Machine Learning](https://www.elastic.co/products/x-pack/machine-learning) to be enabled.

{{event "ml_job"}}

{{fields "ml_job"}}

### Node

`node` interrogates the
{{ url "elasticsearch-cluster-nodes-info" "Cluster API endpoint" }} of
Elasticsearch to get cluster nodes information. It only fetches the data from the `_local` node so it must
run on each Elasticsearch node.

{{event "node"}}

{{fields "node"}}

### Node stats

`node_stats` interrogates the
{{ url "elasticsearch-cluster-nodes-stats" "Cluster API endpoint" }} of
Elasticsearch to get the cluster nodes statistics. The data received is only for the local node so the Agent has
to be run on each Elasticsearch node.

NOTE: The indices stats are node-specific. That means for example the total number of docs reported by all nodes together is not the total number of documents in all indices as there can also be replicas.

{{event "node_stats"}}

{{fields "node_stats"}}

### Pending tasks

{{event "pending_tasks"}}

{{fields "pending_tasks"}}

### Shard

`shard` interrogates the
{{ url "elasticsearch-cluster-state-6.2" "Cluster State API endpoint" }} to fetch
information about all shards.

{{event "shard"}}

{{fields "shard"}}
