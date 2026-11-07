{{- generatedHeader }}
# Qdrant Integration for Elastic

## Overview

The Qdrant integration collects metrics from [Qdrant](https://qdrant.tech), the open-source vector database used for semantic search and retrieval augmented generation (RAG). It shows the REST traffic each node serves (requests by endpoint and status, response time), the size of each collection (points and vectors), background work (running optimizations, update queue) and the health of a cluster (dead replicas, shard transfers, snapshots).

### Compatibility

This integration was tested with the `/metrics` output of Qdrant 1.20. The metric names it uses are defined in `src/common/metrics` of the Qdrant source.

If the Qdrant setting `service.metrics_prefix` is set, every metric name gets that prefix and is not mapped by this integration. Leave it unset.

Kibana 9.2.0 or later is required, because the dashboard uses the ES|QL `TS` command.

### How it works

Qdrant serves Prometheus metrics on the `/metrics` path of its REST API (port `6333` by default), with no extra setting. The Elastic Agent scrapes that endpoint with the Prometheus input and the ingest pipeline maps each metric to a field under `qdrant.*`. The labels of each series (`id` for the collection name, `method`, `endpoint` and `status` for REST responses) are kept under `qdrant.labels.*`.

## What data does this integration collect?

The `metrics` data stream collects:

* **REST API**: responses by `method`, `endpoint` and `status`, response time histogram and longest response time.
* **Collections**: number of collections and vectors, points and vectors per collection, running optimizations, update queue length and deferred points.
* **Cluster**: distributed mode, active and dead replicas, incoming, outgoing and failed shard transfers.
* **Snapshots**: snapshots created, snapshot creation and recovery in progress.
* **Process**: resident and allocated memory, recovery mode.

gRPC metrics and the experimental hardware usage metrics (`collection_hardware_metric_*`) are not collected. The **Metrics Filters Include** setting lists the metrics that are scraped.

### Supported use cases

* Follow search and upsert traffic and latency per endpoint, and catch a rise in 5xx or 4xx responses.
* Watch collections grow and check that optimizations and the update queue keep up with writes.
* Detect dead replicas and failed shard transfers in a Qdrant cluster.

## What do I need to use this integration?

* A Qdrant node reachable over HTTP from the Elastic Agent.
* When Qdrant has an API key, `/metrics` requires it too. Put the key in a file and set **Bearer Token File**: Qdrant accepts the key in the `Authorization: Bearer` header. For HTTPS, set **SSL Configuration**.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard / configure

1. In Kibana, go to **Management > Integrations** and add the **Qdrant** integration.
2. Under **Hosts**, list the Qdrant nodes as `host:port`, for example `localhost:6333`. In a cluster, list every node: each node reports the requests it served.
3. Optionally change the collection **Period** (default `10s`).
4. Assign the integration to an Elastic Agent policy and deploy it.

When Qdrant runs on Kubernetes, use [Kubernetes autodiscover](https://www.elastic.co/docs/reference/fleet/kubernetes-provider) conditions to scrape every Qdrant pod, for example `${kubernetes.pod.ip}:6333`.

### Validation

Open the **[Metrics Qdrant] Overview** dashboard and check that the panels show data. In **Discover**, filter on `data_stream.dataset: qdrant.metrics` to see the documents.

## Troubleshooting

* No data: check that `curl http://<host>:6333/metrics` from the agent host returns lines such as `collections_total`. A `401` response means the node has an API key: set **Bearer Token File**.
* Latency panel empty while the others have data: histograms are sent as the difference between two scrapes, so the first scrape after the agent starts has empty buckets, and an endpoint that received no requests in the period has nothing to show.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

Each scrape produces one document for each combination of labels: one for the node, one for each collection and one for each REST method, endpoint and status. The number of documents grows with the number of collections and of distinct endpoints called.

## Reference

### Metrics

{{event "metrics"}}

{{fields "metrics"}}

### Inputs used

{{ inputDocs }}

## Additional resources

* [Qdrant monitoring](https://qdrant.tech/documentation/guides/monitoring/)
* [Qdrant security (API keys)](https://qdrant.tech/documentation/guides/security/)
