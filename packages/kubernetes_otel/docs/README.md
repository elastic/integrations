# Kubernetes OpenTelemetry Assets

Kubernetes OpenTelemetry Assets must be used with OpenTelemetry data. With this package will be installed assets to monitor [Kubernetes clusters](https://kubernetes.io/).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to ingest opentelemetry data using the OpenTelemetry Operator, see the
[Elastic Distribution for OTel Collector](https://www.elastic.co/docs/solutions/observability/get-started/opentelemetry/quickstart) quickstart guide.

## Assets

### Alert rule templates

Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

The following alert rule templates are available:

**[K8s OTel] Container CPU throttling**

Alerts when containers are using more than 90% of their CPU limit. Throttled containers experience increased latency without triggering crashes or OOMKills, making them hard to detect without explicit monitoring.

**[K8s OTel] Container memory near limit**

Alerts when containers are using more than 90% of their memory limit. Containers approaching their memory limit will be OOMKilled, causing restarts and service disruption.

**[K8s OTel] DaemonSet mis-scheduled or not ready**

Alerts when a DaemonSet has misscheduled nodes (pods running where they shouldn't) or is not fully scheduled (current < desired). Indicates node selector, taint/toleration, or scheduling issues.

**[K8s OTel] Deployment unavailable replicas**

Alerts when a Kubernetes deployment has fewer available replicas than desired, indicating the deployment cannot maintain its target replica count. Common causes: rolling update failures, resource starvation, image pull errors.

**[K8s OTel] HPA at max replicas**

Alerts when a HorizontalPodAutoscaler has scaled to its maximum replica count. This means demand is outpacing the autoscaler's ability to scale, and pods may start becoming resource-constrained or pending.

**[K8s OTel] Job failures**

Alerts when Kubernetes Jobs have failed pods. Non-zero failed pod counts indicate processing failures in batch workloads. Repeated failures in CronJobs can cause a backlog of active jobs.

**[K8s OTel] Node CPU saturation**

Alerts when a node's average CPU usage exceeds a configurable threshold. High CPU usage causes scheduling failures, pod throttling, and degraded workload performance. Threshold should be calibrated to your node's allocatable CPU.

**[K8s OTel] Node disk pressure**

Alerts when any Kubernetes node reports the DiskPressure condition. This is a warning signal that the node is running low on disk space and may begin evicting pods.

**[K8s OTel] Node filesystem saturation**

Alerts when a node's filesystem usage exceeds 85% of capacity. Disk pressure triggers pod evictions and can destabilise the node.

**[K8s OTel] Node memory pressure**

Alerts when any Kubernetes node reports the MemoryPressure condition. This is a warning signal that the node is running low on memory and may begin evicting pods.

**[K8s OTel] Node memory saturation**

Alerts when a node's memory working set exceeds a configurable threshold. High memory usage triggers OOM kills and pod evictions. Threshold should be calibrated to your node's allocatable memory.

**[K8s OTel] Node not ready**

Alerts when any Kubernetes node has condition_ready == 0, indicating the node is not ready to accept workloads. Pods on NotReady nodes are eventually evicted. Common causes: kubelet crashes, network partitions, resource exhaustion.

**[K8s OTel] OOMKilled containers**

Alerts when containers have been OOMKilled — terminated by the kernel OOM killer for exceeding their memory limit. Indicates the container's memory limit is too low or it has a memory leak.

**[K8s OTel] Persistent volume space low**

Alerts when PersistentVolumes have less than 20% space remaining. Running out of volume space causes application write failures and potential data loss.

**[K8s OTel] Pod CrashLoopBackOff**

Alerts when containers have a high restart count, indicating CrashLoopBackOff. Rapidly increasing restarts mean a container is repeatedly crashing and being restarted by the kubelet.

**[K8s OTel] Pods in Failed phase**

Alerts when pods are in Failed phase (phase == 4). Failed pods have terminated with an error and will not be restarted. May indicate persistent issues requiring operator intervention.

**[K8s OTel] Pods stuck in Pending phase**

Alerts when pods are stuck in Pending phase (phase == 1). Pending pods cannot be scheduled — typically due to insufficient node resources, node affinity/taint mismatches, or missing PVCs. Sustained Pending pods are a proxy for scheduling latency.

**[K8s OTel] StatefulSet replicas not ready**

Alerts when a StatefulSet has fewer ready pods than desired. StatefulSets manage stateful applications with stable identities, so missing replicas can cause data availability issues.



### SLO Templates

SLO templates provide pre-defined configurations for creating SLOs in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/solutions/observability/incident-management/service-level-objectives-slos).

SLO templates require Elastic Stack version 9.4.0 or later.

**The following SLO templates are available:**

<details>
<summary>View the SLO templates</summary>

| Name | Description |
|---|---|
| [Kubernetes OTel] DaemonSet Scheduling Availability 99.0% Rolling 30 Days | This SLO tracks the scheduling availability of Kubernetes DaemonSets using OTel metrics, ensuring that 99.0% of time intervals have each DaemonSet running on all eligible nodes over a rolling period of 30 days. DaemonSets are critical for node-level infrastructure services (monitoring agents, log collectors, security agents, network plugins). |
| [Kubernetes OTel] Deployment Replica Availability 99.5% Rolling 30 Days | This SLO tracks the availability of Kubernetes Deployments using OTel metrics, ensuring that 99.5% of time intervals have each Deployment meeting its desired replica count over a rolling period of 30 days to maintain reliable application serving capacity. When k8s.deployment.available \< k8s.deployment.desired, the Deployment has fewer healthy replicas than configured, indicating reduced capacity or total unavailability for the hosted application. |
| [Kubernetes OTel] Job Completion Success Rate 99.0% Rolling 30 Days | This SLO tracks the success rate of Kubernetes Jobs using OTel metrics, ensuring that 99.0% of time intervals show Jobs completing without failures over a rolling period of 30 days. Jobs represent batch workloads (ETL, backups, data pipelines, scheduled tasks) with clear completion semantics. |
| [Kubernetes OTel] StatefulSet Replica Availability 99.5% Rolling 30 Days | This SLO tracks the availability of Kubernetes StatefulSets using OTel metrics, ensuring that 99.5% of time intervals have each StatefulSet meeting its desired replica count over a rolling period of 30 days. StatefulSets manage stateful workloads (databases, message queues, caches) where pod identity and ordering matter — making availability critical for data integrity. |

</details>


