# GKE

## Metrics

The `gke` dataset fetches metrics from [GKE](https://cloud.google.com/kubernetes-engine) in Google Cloud Platform. It contains all GA metrics exported from the [GCP GKE Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-container).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP GKE does not use zones so `us-central1-a` will return nothing. If no region is specified, it will return metrics from all regions.

## Sample Event
    
An example event for `gke` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev",
            "name": "elastic-obs-integrations-dev"
        },
        "instance": {
            "id": "4751091017865185079",
            "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
        },
        "machine": {
            "type": "e2-medium"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.gke",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "gke": {
            "container": {
                "cpu": {
                    "core_usage_time": {
                        "sec": 15
                    }
                }
            }
        },
        "labels": {
            "user": {
                "goog-gke-node": ""
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
    },
    "metricset": {
        "name": "gke",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| gcp.gke.container.cpu.core_usage_time.sec | Cumulative CPU usage on all cores used by the container in seconds. Sampled every 60 seconds. | double | counter |
| gcp.gke.container.cpu.limit_cores.value | CPU cores limit of the container. Sampled every 60 seconds. | double | gauge |
| gcp.gke.container.cpu.limit_utilization.pct | The fraction of the CPU limit that is currently in use on the instance. This value cannot exceed 1 as usage cannot exceed the limit. Sampled every 60 seconds. After sampling, data is not visible for up to 240 seconds. | double | gauge |
| gcp.gke.container.cpu.request_cores.value | Number of CPU cores requested by the container. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | double | gauge |
| gcp.gke.container.cpu.request_utilization.pct | The fraction of the requested CPU that is currently in use on the instance. This value can be greater than 1 as usage can exceed the request. Sampled every 60 seconds. After sampling, data is not visible for up to 240 seconds. | double | gauge |
| gcp.gke.container.ephemeral_storage.limit.bytes | Local ephemeral storage limit in bytes. Sampled every 60 seconds. | long | gauge |
| gcp.gke.container.ephemeral_storage.request.bytes | Local ephemeral storage request in bytes. Sampled every 60 seconds. | long | gauge |
| gcp.gke.container.ephemeral_storage.used.bytes | Local ephemeral storage usage in bytes. Sampled every 60 seconds. | long | gauge |
| gcp.gke.container.memory.limit.bytes | Memory limit of the container in bytes. Sampled every 60 seconds. | long | gauge |
| gcp.gke.container.memory.limit_utilization.pct | The fraction of the memory limit that is currently in use on the instance. This value cannot exceed 1 as usage cannot exceed the limit. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | double | gauge |
| gcp.gke.container.memory.page_fault.count | Number of page faults, broken down by type, major and minor. | long | counter |
| gcp.gke.container.memory.request.bytes | Memory request of the container in bytes. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | long | gauge |
| gcp.gke.container.memory.request_utilization.pct | The fraction of the requested memory that is currently in use on the instance. This value can be greater than 1 as usage can exceed the request. Sampled every 60 seconds. After sampling, data is not visible for up to 240 seconds. | double | gauge |
| gcp.gke.container.memory.used.bytes | Memory usage in bytes. Sampled every 60 seconds. | long | gauge |
| gcp.gke.container.restart.count | Number of times the container has restarted. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | long | counter |
| gcp.gke.container.uptime.sec | Time in seconds that the container has been running. Sampled every 60 seconds. | double | gauge |
| gcp.gke.node.cpu.allocatable_cores.value | Number of allocatable CPU cores on the node. Sampled every 60 seconds. | double | gauge |
| gcp.gke.node.cpu.allocatable_utilization.pct | The fraction of the allocatable CPU that is currently in use on the instance. Sampled every 60 seconds. After sampling, data is not visible for up to 240 seconds. | double | gauge |
| gcp.gke.node.cpu.core_usage_time.sec | Cumulative CPU usage on all cores used on the node in seconds. Sampled every 60 seconds. | double | counter |
| gcp.gke.node.cpu.total_cores.value | Total number of CPU cores on the node. Sampled every 60 seconds. | double | gauge |
| gcp.gke.node.ephemeral_storage.allocatable.bytes | Local ephemeral storage bytes allocatable on the node. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.ephemeral_storage.inodes_free.value | Free number of inodes on local ephemeral storage. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.ephemeral_storage.inodes_total.value | Total number of inodes on local ephemeral storage. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.ephemeral_storage.total.bytes | Total ephemeral storage bytes on the node. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.ephemeral_storage.used.bytes | Local ephemeral storage bytes used by the node. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.memory.allocatable.bytes | Cumulative memory bytes used by the node. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.memory.allocatable_utilization.pct | The fraction of the allocatable memory that is currently in use on the instance. This value cannot exceed 1 as usage cannot exceed allocatable memory bytes. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | double | gauge |
| gcp.gke.node.memory.total.bytes | Number of bytes of memory allocatable on the node. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.memory.used.bytes | Cumulative memory bytes used by the node. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.network.received_bytes.count | Cumulative number of bytes received by the node over the network. Sampled every 60 seconds. | long | counter |
| gcp.gke.node.network.sent_bytes.count | Cumulative number of bytes transmitted by the node over the network. Sampled every 60 seconds. | long | counter |
| gcp.gke.node.pid_limit.value | The max PID of OS on the node. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node.pid_used.value | The number of running process in the OS on the node. Sampled every 60 seconds. | long | gauge |
| gcp.gke.node_daemon.cpu.core_usage_time.sec | Cumulative CPU usage on all cores used by the node level system daemon in seconds. Sampled every 60 seconds. | double | counter |
| gcp.gke.node_daemon.memory.used.bytes | Memory usage by the system daemon in bytes. Sampled every 60 seconds. | long | gauge |
| gcp.gke.pod.network.received.bytes | Cumulative number of bytes received by the pod over the network. Sampled every 60 seconds. | long | counter |
| gcp.gke.pod.network.sent.bytes | Cumulative number of bytes transmitted by the pod over the network. Sampled every 60 seconds. | long | counter |
| gcp.gke.pod.volume.total.bytes | Total number of disk bytes available to the pod. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | long | gauge |
| gcp.gke.pod.volume.used.bytes | Number of disk bytes used by the pod. Sampled every 60 seconds. | long | gauge |
| gcp.gke.pod.volume.utilization.pct | The fraction of the volume that is currently being used by the instance. This value cannot be greater than 1 as usage cannot exceed the total available volume space. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | double | gauge |
| gcp.labels.metadata.\* |  | object |  |
| gcp.labels.metrics.\* |  | object |  |
| gcp.labels.resource.\* |  | object |  |
| gcp.labels.system.\* |  | object |  |
| gcp.labels.user.\* |  | object |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
