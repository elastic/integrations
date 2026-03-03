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

### Indices and data streams usage analysis

_Technical preview: please report any issue [here](https://github.com/elastic/integrations/issues), and specify the "elasticsearch" integration_

For version 8.17.1+ of the module and collected data, the integration also installs a transform job called `logs-elasticsearch.index_pivot-default-{VERSION}`. This transform **isn't started by default** (Stack management > Transforms), but will perform the following once activated:

* Read the data from the `index` dataset, produced by this very same integration.
* Aggregate the index-level stats in data-stream-centric insights, such as query count, query time or overall data volume.
* This aggregated data is then processed through an additional, integration-installed, ingest pipeline (`{VERSION}-monitoring_indices`) before being shipped to a `monitoring-indices` index.

You can then visualize the resulting data in the `[Elasticsearch] Indices & data streams usage` dashboard.

![Indices & data streams usage](../img/indices_datastream_view.png)

Apart from some high-level statistics, such as total query count, total query time and total addressable data, the dashboard surfaces usage information centered on two dimensions:

* The [data tier](https://www.elastic.co/guide/en/elasticsearch/reference/current/data-tiers.html).
* The data stream (see note below for details about how this is computed).

#### Tier usage

As data ages, it commonly reduces in relative importance and is commonly stored on less efficient and more cost-effective hardware. Usage count and query time should also proportionally diminish. Various visualizations in the dashboard allow you to verify this assumption on your data, and ensure your ILM policy (and therefore data tier transitions) are aligned with how the data is actually being used.

#### Indices and data streams usage

Other visualizations in the dashboard allow you to compare the relative footprint of each data stream, from a storage, querying and indexing perspective. This can help you identify anomalies, stemming from faulty configuration or poor user behavior.

Both approaches can be used in conjunction, allowing you to fine-tune ILM on a data stream basis (if required) to closely match usage patterns.

⚠️ Important notes:

* The transform job will process all compatible historical data, which has two implications: 1. if you have pre-8.17.1 data, this will not get picked up by the job and 2. it might take time for "live" data to be available, as the transform job works its way through all documents. You can modify the transform job as you please if need be.
* The target index `monitoring-indices` is not controlled by ILM. In case you work on a setup with a high count of indices or with a high retention, you may need to tune the transform job, or [activate ILM on the target index](https://www.elastic.co/guide/en/elasticsearch/reference/current/getting-started-index-lifecycle-management.html#manage-time-series-data-without-data-streams). Per our testing on a cluster with 5000 indices, we generated around 1GB of primary data for each week (your mileage may vary).
* The identification of the data stream is based on the following grok pattern: `^(?:partial-)?(?:restored-)?(?:shrink-.{4}-)?(?:\\.ds-)?(?<elasticsearch.index.datastream>[a-z_0-9\\-\\.]+?)(-(?:\\d{4}\\.\\d{2}(\\.\\d{2})?))?(?:-\\d+)?$`. This should cover all "out of the box" names, but you can modify this to your liking in the `{VERSION}-monitoring_indices` ingest pipeline (though a copy is advised), if you are using non-standard names or would like to aggregate data differently.

