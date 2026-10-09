# GCP GKE OpenTelemetry Assets

This package contains Kibana assets for monitoring [Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine/docs) clusters with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect GKE metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Metric sources

The dashboards read two sets of GKE metrics from Cloud Monitoring. Each set has its own cluster requirements.

### System metrics

System metrics (`kubernetes.io/...`) report CPU, memory, ephemeral storage, network, volumes, restarts, and node conditions for nodes, pods, and containers. They need system monitoring on the cluster (the `SYSTEM` monitoring component), which GKE enables by default. Every dashboard panel that is not listed in [Panels that need kube state metrics](#panels-that-need-kube-state-metrics) uses only system metrics.

### Kube state metrics

Kube state metrics (`prometheus.googleapis.com/kube_.../gauge`) report pod phase, container readiness, and desired, available, and ready replicas for Deployments, StatefulSets, and DaemonSets. They come from the [GKE kube state metrics package](https://cloud.google.com/kubernetes-engine/docs/how-to/kube-state-metrics). A cluster only sends them when all of the following are true:

- The cluster runs GKE 1.27.2-gke.1200 or later. GKE enables the package by default starting with version 1.29.2-gke.2000 for Standard clusters and version 1.27.4-gke.900 for Autopilot clusters.
- Managed Service for Prometheus managed collection is enabled. It's enabled by default for new clusters.
- The `POD`, `DEPLOYMENT`, `STATEFULSET`, and `DAEMONSET` monitoring components are enabled.

To check which monitoring components a cluster has enabled, run:

```sh
gcloud container clusters describe CLUSTER_NAME \
    --location=COMPUTE_LOCATION \
    --format="value(monitoringConfig.componentConfig.enableComponents)"
```

To enable the components the dashboards need, run:

```sh
gcloud container clusters update CLUSTER_NAME \
    --location=COMPUTE_LOCATION \
    --enable-managed-prometheus \
    --monitoring=SYSTEM,POD,DEPLOYMENT,STATEFULSET,DAEMONSET
```

Replace `CLUSTER_NAME` with the name of the cluster and `COMPUTE_LOCATION` with its Compute Engine location.

**Warning:** `--monitoring` replaces the cluster's whole list of monitoring components. It doesn't add to it. Include every component that is already enabled, for example `HPA` or `STORAGE`, or GKE stops collecting it.

Cloud Monitoring bills kube state metrics per sample ingested. They also count against the Cloud Monitoring time series ingestion quota. Refer to [Cloud Monitoring pricing](https://cloud.google.com/stackdriver/pricing) before you enable them on many clusters.

Kube state metrics don't cover system namespaces such as `kube-system`. Pods in those namespaces appear with usage metrics but without a phase or readiness.

A cluster without kube state metrics still appears on every dashboard. Its phase and workload panels show 0 or no rows.

## Setup

1. Optional: enable kube state metrics on your clusters, as described in [Kube state metrics](#kube-state-metrics).
2. Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and add it to an Elastic Agent policy.
3. Set **GCP Project ID** to the project that runs your GKE clusters. To monitor clusters in more than one project, add one input for each project, all with the same dataset name.
4. Add every metric type listed in [Metric types to collect](#metric-types-to-collect) to **Metrics List**, one per line.
5. Set the dataset name to `gcp.gke.otel` so that data is written to the `metrics-gcp.gke.otel-default` data stream, which these dashboards query.

The input looks up metric descriptors once, when Elastic Agent starts, and skips any listed metric type that has no descriptor in the project yet. Cloud Monitoring creates the descriptor for a kube state metric the first time a cluster in the project sends it. After a project first enables kube state metrics, restart Elastic Agent so that the input starts collecting them.

## Metric types to collect

The dashboards use 58 metric types: 46 system metrics and 12 kube state metrics.

System metrics, reported for the `k8s_node`, `k8s_pod`, and `k8s_container` monitored resources:

```text
kubernetes.io/container/cpu/core_usage_time
kubernetes.io/container/cpu/limit_cores
kubernetes.io/container/cpu/limit_utilization
kubernetes.io/container/cpu/request_cores
kubernetes.io/container/cpu/request_utilization
kubernetes.io/container/ephemeral_storage/limit_bytes
kubernetes.io/container/ephemeral_storage/request_bytes
kubernetes.io/container/ephemeral_storage/used_bytes
kubernetes.io/container/memory/limit_bytes
kubernetes.io/container/memory/limit_utilization
kubernetes.io/container/memory/page_fault_count
kubernetes.io/container/memory/request_bytes
kubernetes.io/container/memory/request_utilization
kubernetes.io/container/memory/used_bytes
kubernetes.io/container/restart_count
kubernetes.io/container/uptime
kubernetes.io/node/cpu/allocatable_cores
kubernetes.io/node/cpu/allocatable_utilization
kubernetes.io/node/cpu/core_usage_time
kubernetes.io/node/cpu/total_cores
kubernetes.io/node/ephemeral_storage/allocatable_bytes
kubernetes.io/node/ephemeral_storage/inodes_free
kubernetes.io/node/ephemeral_storage/inodes_total
kubernetes.io/node/ephemeral_storage/total_bytes
kubernetes.io/node/ephemeral_storage/used_bytes
kubernetes.io/node/interruption_count
kubernetes.io/node/latencies/startup
kubernetes.io/node/logs/input_bytes
kubernetes.io/node/memory/allocatable_bytes
kubernetes.io/node/memory/allocatable_utilization
kubernetes.io/node/memory/total_bytes
kubernetes.io/node/memory/used_bytes
kubernetes.io/node/network/received_bytes_count
kubernetes.io/node/network/sent_bytes_count
kubernetes.io/node/pid_limit
kubernetes.io/node/pid_used
kubernetes.io/node/status_condition
kubernetes.io/node_daemon/cpu/core_usage_time
kubernetes.io/node_daemon/memory/used_bytes
kubernetes.io/pod/ephemeral_storage/used_bytes
kubernetes.io/pod/latencies/pod_first_ready
kubernetes.io/pod/network/received_bytes_count
kubernetes.io/pod/network/sent_bytes_count
kubernetes.io/pod/volume/total_bytes
kubernetes.io/pod/volume/used_bytes
kubernetes.io/pod/volume/utilization
```

Kube state metrics, reported for the `prometheus_target` monitored resource:

```text
prometheus.googleapis.com/kube_daemonset_status_desired_number_scheduled/gauge
prometheus.googleapis.com/kube_daemonset_status_number_misscheduled/gauge
prometheus.googleapis.com/kube_daemonset_status_number_ready/gauge
prometheus.googleapis.com/kube_daemonset_status_updated_number_scheduled/gauge
prometheus.googleapis.com/kube_deployment_spec_replicas/gauge
prometheus.googleapis.com/kube_deployment_status_replicas_available/gauge
prometheus.googleapis.com/kube_deployment_status_replicas_updated/gauge
prometheus.googleapis.com/kube_pod_container_status_ready/gauge
prometheus.googleapis.com/kube_pod_status_phase/gauge
prometheus.googleapis.com/kube_statefulset_replicas/gauge
prometheus.googleapis.com/kube_statefulset_status_replicas_ready/gauge
prometheus.googleapis.com/kube_statefulset_status_replicas_updated/gauge
```

For the kind, unit, and labels of each system metric, refer to [Kubernetes metrics](https://cloud.google.com/monitoring/api/metrics_kubernetes). For the kube state metrics, refer to the [kube state metrics package](https://cloud.google.com/kubernetes-engine/docs/how-to/kube-state-metrics).

## Panels that need kube state metrics

Without kube state metrics, the following panels show 0, no rows, or N/A, and the listed table columns stay empty. All other panels work with system metrics alone.

| Dashboard | Panels | Table columns |
|-----------|--------|---------------|
| **[GCP OTel] GKE Overview** | Top 10 clusters by problem pods, Top 10 namespaces by problem pods, Top 10 namespaces by containers not ready, Deployments, StatefulSets, DaemonSets, Workloads short of desired, Deployment replicas over time, DaemonSet scheduling over time, Top 10 clusters by replica shortfall, List of workloads short of desired, Total pods, Running, Pending, Failed, Succeeded, Unknown, Pods by phase, Pods by phase over time, List of containers not ready | **Problem pods** in List of clusters. **Problem pods**, **Pods**, and **Deployments** in List of namespaces. **Phase** in List of pods. |
| **[GCP OTel] GKE Cluster Detail** | Deployments, List of workloads short of desired, Total pods, Running, Pending, Failed, Succeeded, Unknown | |
| **[GCP OTel] GKE Node Detail** | None | |
| **[GCP OTel] GKE Namespace Detail** | Pods by phase over time, Total pods, Running, Pending, Failed, Succeeded, Unknown, List of workloads | **Phase** in List of pods. |
| **[GCP OTel] GKE Pod Detail** | Phase, in the header | **Ready** in List of containers. |

## Dashboards

Start from the overview. Click a hexagon or a table row to open the matching detail dashboard, filtered to that cluster, node, namespace, or pod.

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] GKE Overview** | Fleet view of GKE clusters, in sections for clusters, nodes, namespaces, workload resources, and pods. Cluster health, CPU, memory, and ephemeral storage use against allocatable capacity and requests, log volume, a hexagon map of node saturation and readiness, node interruptions, startup time, and network traffic, top namespaces and pods by usage and restarts, pods closest to their CPU limit, the fullest PersistentVolumeClaims, pods by phase, workloads short of desired replicas, containers not ready, and a list table for clusters, nodes, namespaces, and pods. |
| **[GCP OTel] GKE Cluster Detail** | One GKE cluster. CPU, memory, and ephemeral storage used against requests and allocatable capacity, the nodes and their network traffic, the namespaces, workloads, and pods in the cluster, and log volume by type and by node. Open it from the clusters table on the overview. |
| **[GCP OTel] GKE Node Detail** | One GKE node. Readiness and pressure conditions, CPU, memory, ephemeral storage, PID, and network capacity, log volume, and node daemon resource use. Open it from a hexagon or a node name on the overview or on Cluster Detail. |
| **[GCP OTel] GKE Namespace Detail** | One namespace in one cluster. CPU and memory against requests and limits, PersistentVolumeClaim fill, pod phases, and the pods and workloads in the namespace. Open it from a namespace or workload row on the overview or on Cluster Detail. |
| **[GCP OTel] GKE Pod Detail** | One pod. Phase, restarts, time to ready, CPU and memory against requests and limits, volume usage, a container breakdown, network I/O, memory composition, and restarts and page faults by container. Open it from a pod row on the overview, Cluster Detail, or Namespace Detail. |
