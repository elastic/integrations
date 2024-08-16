# Kubernetes integration

This integration is used to collect logs and metrics from 
[Kubernetes clusters](https://kubernetes.io/). Time series [index mode](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds.html) enabled for metrics data streams.

| |
| ------------- | 
| **This integration requires kube-state-metrics, which is not included with Kubernetes by default. For dashboards to properly populate, the [kube-state-metrics service must be deployed to your Kubernetes cluster](https://github.com/kubernetes/kube-state-metrics)** |


As one of the main pieces provided for Kubernetes monitoring, this integration is capable of fetching metrics from several components:

- [kubelet](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)
- [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics)
- [apiserver](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [controller-manager](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [scheduler](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)
- [proxy](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/)

Some of the previous components are running on each of the Kubernetes nodes (like `kubelet` or `proxy`) while others provide
a single cluster-wide endpoint. This is important to determine the optimal configuration and running strategy
for the different datasets included in the integration.


### Kubernetes endpoints and metricsets

Kubernetes module is a bit complex as its internal datasets require access to a wide variety of endpoints.

This section highlights and introduces some groups of datasets with similar endpoint access needs. 
For more details on the datasets see `configuration example` and the `datasets` sections below.


### node / system / pod / container / module / volume

The datasets `container`, `node`, `pod`, `system` and `volume` require access to the `kubelet endpoint` in each of
the Kubernetes nodes, hence it's recommended to include them as part
of an `Agent DaemonSet` or standalone Agents running on the hosts.

Depending on the version and configuration of Kubernetes nodes, `kubelet` might provide a read only http port (typically 10255),
which is used in some configuration examples. But in general, and lately, this endpoint requires SSL (`https`) access
(to port 10250 by default) and token based authentication.


#### state_* and event

State_* datasets are enabled by default.

All datasets with the `state_` prefix require `hosts` field pointing to `kube-state-metrics`
service within the cluster. As the service provides cluster-wide metrics, there's no need to fetch them per node,
hence the recommendation is to run these datasets as part of an `Agent Deployment` with one only replica.

 Generally `kube-state-metrics` runs a `Deployment` and is accessible via a service called `kube-state-metrics` on
`kube-system` namespace, which will be the service to use in our configuration.


### apiserver

The apiserver dataset requires access to the Kubernetes API, which should be easily available in all Kubernetes
environments. Depending on the Kubernetes configuration, the API access might require SSL (`https`) and token
based authentication.

### proxy

The proxy dataset requires access to the proxy endpoint in each of Kubernetes nodes, hence it's recommended
to configure it as a part of an `Agent DaemonSet`.

### scheduler and controllermanager

These datasets require access to the Kubernetes `controller-manager` and `scheduler` endpoints. By default, these pods
run only on master nodes, and they are not exposed via a Service, but there are different strategies
available for its configuration:

- Create `Kubernetes Services` to make `kube-controller-manager` and `kube-scheduler` available and configure
 the datasets to point to these services as part of an `Agent Deployment`.
- Run these datasets as part an `Agent Daemonset` (with HostNetwork setting) with a `nodeSelector` to only run on Master nodes.

These datasets are not enabled by default.

Note: In some "As a Service" Kubernetes implementations, like `GKE`, the master nodes or even the pods running on
the masters won't be visible. In these cases it won't be possible to use `scheduler` and `controllermanager` metricsets.

### container-logs

The container-logs dataset requires access to the log files in each Kubernetes node where the container logs are stored.
This defaults to `/var/log/containers/*${kubernetes.container.id}.log`.

#### Routing

The container-logs data stream allows routing logs to a different *dataset* or *namespace* using pod annotations.

For example, suppose you are running Nginx on your Kubernetes cluster, and you want to drive the Nginx container logs into a dedicated dataset or namespace. By annotating the pod with `elastic.co/namespace: nginx`, the integration will send all the container logs to the `nginx` namespace.

To learn more about routing container-logs, see https://docs.elastic.co/integrations/kubernetes/container-logs.

#### Preserve original event

The agent can be configured to set the tag `preserve_original_event` on container-logs using pod annotation.

For example, suppose you are routing your Nginx container logs into a dedicated dataset or namespace as described above to make use of the Nginx fleet integration. Enabling preserve_original_event on the Nginx integration will have no effect
since the logs were shipped via kubernetes integration and not Nginx. As well, you may not want to have all original events from all Nginx pods preserved as well.

By annotating the pod with `elastic.co/preserve_original_event: 'true'`, the integration will add the tag `preserve_original_event` as it would be done by the `nginx` integration otherwise.

### audit-logs

The audit-logs dataset requires access to the log files on each Kubernetes node where the audit logs are stored.
This defaults to `/var/log/kubernetes/kube-apiserver-audit.log`.

## Compatibility

The Kubernetes package is tested with Kubernetes [1.29.x - 1.31.x] versions

## Dashboard

Kubernetes integration is shipped including default dashboards for `apiserver`, `controllermanager`, `overview`, `proxy` and `scheduler`.

If you are using HA for those components, be aware that when gathering data from all instances the dashboard will usually show the average of the metrics. For those scenarios filtering by hosts or service address is possible.

Cluster selector in `overview` dashboard helps in distinguishing and filtering metrics collected from multiple clusters. If you want to focus on a subset of the Kubernetes clusters for monitoring a specific scenario, this cluster selector could be a handy tool. Note that this selector gets populated from the `orchestrator.cluster.name` field that may not always be available. This field gets its value from sources like `kube_config`, `kubeadm-config` configMap, and Google Cloud's meta API for GKE. If the sources mentioned above don't provide this value, metricbeat will not report it. However, you can always use [processors](https://www.elastic.co/guide/en/beats/metricbeat/current/defining-processors.html) to set this field and utilize it in the `cluster overview` dashboard.
