# Couchbase Integration

## Overview

The Couchbase integration allows you to monitor your Couchbase instance. Couchbase Server is an open-source, distributed multi-model NoSQL document-oriented database software package optimized for interactive applications.

Use the Couchbase integration to collect metrics related to the bucket, cluster, node, and sync gateway. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, you could use the data from this integration to know when there are more than some number of failed authentication requests for a single piece of content in a given time period. You could also use the data to troubleshoot the underlying issue by looking at the documents ingested in Elasticsearch.

## Data streams

The Couchbase integration collects metrics data.

Metrics give you insight into the state of the Couchbase. Metrics data streams collected by the Couchbase integration include [Bucket](https://docs.couchbase.com/server/current/rest-api/rest-buckets-summary.html),  [Cluster](https://docs.couchbase.com/server/current/rest-api/rest-cluster-details.html), [Node](https://docs.couchbase.com/server/current/rest-api/rest-cluster-details.html), [Cache](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#cache), [Couchbase Lite Replication](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#cbl_replication_pull), [Database](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#database), [Delta Sync](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#delta_sync), [Eventing](https://developer.couchbase.com/tutorial-monitoring-eventing-service?learningPath=learn/couchbase-monitoring-guide#get-cluster-eventing-service-stats), [GSI views](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#gsi_views), [Import](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#shared_bucket_import), [Index](https://developer.couchbase.com/tutorial-monitoring-index-service#get-cluster-index-service-stats), [Query](https://developer.couchbase.com/tutorial-monitoring-query-service?learningPath=learn/couchbase-monitoring-guide#get-cluster-query-service-stats), [Resource Utilization](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#resource_utilization), [Security](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#security), and [XDCR](https://docs.couchbase.com/server/current/rest-api/rest-bucket-stats.html) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses:
- `http` metricbeat module to collect `bucket`, `cluster`, `eventing`, `index`, `query`, and `xdcr` metrics.
- `couchbase` metricbeat module to collect `node` metrics.
- `prometheus` metricbeat module to collect `cache`, `cbl_replication`, `database_stats`, `delta_sync`, `gsi_views`, `import`, `resource`, and `security` metrics.

Note: For Couchbase cluster setup, there is an ideal scenario of a single host with administrator access for the entire cluster to collect metrics. Providing multiple hosts from the same cluster might lead to data duplication. In the case of multiple clusters, adding a new integration to collect data from different cluster hosts is a good option.

## Compatibility

This integration has been tested against Couchbase `v6.6`, `v7.0`, and `v7.1`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Couchbase, you must know the host(s) and the administrator credentials for the Couchbase instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://Administrator:password@localhost:8091`

## Setup

In order to collect data using [Sync Gateway](https://www.couchbase.com/products/sync-gateway), follow the steps given below:
- Download and configure [Sync Gateway](https://docs.couchbase.com/sync-gateway/current/get-started-install.html)
- Download and configure [Sync Gateway Promethus Exporter](https://github.com/couchbaselabs/couchbase-sync-gateway-exporter.git) and provide Sync Gateway Host using --sgw.url flag while running the Exporter App
- Example configuration: `--sgw.url=http://sgw:4985`

## Metrics reference

### Bucket

This is the `bucket` data stream. A bucket is a logical container for a related set of items such as key-value pairs or documents.

{{event "bucket"}}

{{fields "bucket"}}

### Cluster

This is the `cluster` data stream. A cluster is a collection of nodes that are accessed and managed as a single group. Each node is an equal partner in orchestrating the cluster to provide facilities such as operational information (monitoring) or managing cluster membership of nodes and the health of nodes.

{{event "cluster"}}

{{fields "cluster"}}

### Query Index

This is the `query_index` data stream. The Query service enables you to issue queries to extract data from the Couchbase server. The Index collects statistics provided by the Index service.

{{event "query_index"}}

{{fields "query_index"}}
