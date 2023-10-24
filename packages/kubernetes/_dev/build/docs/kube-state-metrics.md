# kube-state-metrics

Kube-state Metrics version should be aligned with the Kubernetes version of your cluster. Follow  relevant [kubernetes/kube-state-metrics compatibility-matrix](https://github.com/kubernetes/kube-state-metrics#compatibility-matrix) for more information.

## Metrics

If Leader Election is activated (default behaviour) only the `elastic agent` which holds the leadership lock
will retrieve metrics from the `kube_state_metrics`.
This is relevant in multi-node kubernetes cluster and prevents duplicate data.

### state_container

This is the `state_container` dataset of the Kubernetes package. It collects container related
metrics from `kube_state_metrics`.

{{event "state_container"}}

{{fields "state_container"}}

### state_cronjob

This is the `state_cronjob` dataset of the Kubernetes package. It collects cronjob related
metrics from `kube_state_metrics`.

>Important Note: Please make sure that you install latest kube-state metrics version for this datataset to appear. 
Eg. Kube-state-metrics v2.3.0 was not reporting cron_job metrics for Kubernetes v1.25.0

{{event "state_cronjob"}}

{{fields "state_cronjob"}}

### state_daemonset

This is the `state_daemonset` dataset of the Kubernetes package. It collects daemonset related
metrics from `kube_state_metrics`.

{{event "state_daemonset"}}

{{fields "state_daemonset"}}

### state_deployment

This is the `state_deployment` dataset of the Kubernetes package. It collects deployment related
metrics from `kube_state_metrics`.

{{event "state_deployment"}}

{{fields "state_deployment"}}

### state_job

This is the `state_job` dataset of the Kubernetes package. It collects job related
metrics from `kube_state_metrics`.

{{event "state_job"}}

{{fields "state_job"}}

### state_node

This is the `state_node` dataset of the Kubernetes package. It collects node related
metrics from `kube_state_metrics`.

{{event "state_node"}}

{{fields "state_node"}}

### state_persistentvolume

This is the `state_persistentvolume` dataset of the Kubernetes package. It collects 
PersistentVolume related metrics from `kube_state_metrics`.

{{event "state_persistentvolume"}}

{{fields "state_persistentvolume"}}

### state_persistentvolumeclaim

This is the `state_persistentvolumeclaim` dataset of the Kubernetes package. It collects 
PersistentVolumeClaim related metrics from `kube_state_metrics`.

{{event "state_persistentvolumeclaim"}}

{{fields "state_persistentvolumeclaim"}}

### state_pod

This is the `state_pod` dataset of the Kubernetes package. It collects 
Pod related metrics from `kube_state_metrics`.

{{event "state_pod"}}

{{fields "state_pod"}}

### state_replicaset

This is the `state_replicaset` dataset of the Kubernetes package. It collects 
Replicaset related metrics from `kube_state_metrics`.

{{event "state_replicaset"}}

{{fields "state_replicaset"}}

### state_resourcequota

This is the `state_resourcequota` dataset of the Kubernetes package. It collects ResourceQuota related metrics
from `kube_state_metrics`.

{{event "state_resourcequota"}}

{{fields "state_resourcequota"}}

### state_service

This is the `state_service` dataset of the Kubernetes package. It collects 
Service related metrics from `kube_state_metrics`.

{{event "state_service"}}

{{fields "state_service"}}

### state_statefulset

This is the `state_statefulset` dataset of the Kubernetes package.

{{event "state_statefulset"}}

{{fields "state_statefulset"}}

### state_storageclass

This is the `state_storageclass` dataset of the Kubernetes package. It collects 
StorageClass related metrics from `kube_state_metrics`.

{{event "state_storageclass"}}

{{fields "state_storageclass"}}