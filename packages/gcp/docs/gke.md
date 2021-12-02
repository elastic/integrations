# Google Kubernetes Engine (GKE)

## Metrics

This is the `gke` dataset.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.gke.container.cpu.core_usage_time.value | Cumulative CPU usage on all cores used by the container in seconds. Sampled every 60 seconds. | double |
| gcp.gke.container.cpu.limit_cores.value | CPU cores limit of the container. Sampled every 60 seconds. | double |
| gcp.gke.container.cpu.limit_utilization.value | The fraction of the CPU limit that is currently in use on the instance. This value cannot exceed 1 as usage cannot exceed the limit. Sampled every 60 seconds. After sampling, data is not visible for up to 240 seconds. | double |
| gcp.gke.container.cpu.request_cores.value | Number of CPU cores requested by the container. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | double |
| gcp.gke.container.cpu.request_utilization.value | The fraction of the requested CPU that is currently in use on the instance. This value can be greater than 1 as usage can exceed the request. Sampled every 60 seconds. After sampling, data is not visible for up to 240 seconds. | double |
| gcp.gke.container.ephemeral_storage.limit_bytes.value | Local ephemeral storage limit in bytes. Sampled every 60 seconds. | long |
| gcp.gke.container.ephemeral_storage.request_bytes.value | Local ephemeral storage request in bytes. Sampled every 60 seconds. | long |
| gcp.gke.container.ephemeral_storage.used_bytes.value | Local ephemeral storage usage in bytes. Sampled every 60 seconds. | long |
| gcp.gke.container.memory.limit_bytes.value | Memory limit of the container in bytes. Sampled every 60 seconds. | long |
| gcp.gke.container.memory.limit_utilization.value | The fraction of the memory limit that is currently in use on the instance. This value cannot exceed 1 as usage cannot exceed the limit. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | double |
| gcp.gke.container.memory.page_fault_count.value | Number of page faults, broken down by type, major and minor. | long |
| gcp.gke.container.memory.request_bytes.value | Memory request of the container in bytes. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | long |
| gcp.gke.container.memory.request_utilization.value | The fraction of the requested memory that is currently in use on the instance. This value can be greater than 1 as usage can exceed the request. Sampled every 60 seconds. After sampling, data is not visible for up to 240 seconds. | double |
| gcp.gke.container.memory.used_bytes.value | Memory usage in bytes. Sampled every 60 seconds. | long |
| gcp.gke.container.restart_count.value | Number of times the container has restarted. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | long |
| gcp.gke.container.uptime.value | Time in seconds that the container has been running. Sampled every 60 seconds. | double |
| gcp.gke.node.cpu.allocatable_cores.value | Number of allocatable CPU cores on the node. Sampled every 60 seconds. | double |
| gcp.gke.node.cpu.allocatable_utilization.value | The fraction of the allocatable CPU that is currently in use on the instance. Sampled every 60 seconds. After sampling, data is not visible for up to 240 seconds. | double |
| gcp.gke.node.cpu.core_usage_time.value | Cumulative CPU usage on all cores used on the node in seconds. Sampled every 60 seconds. | double |
| gcp.gke.node.cpu.total_cores.value | Total number of CPU cores on the node. Sampled every 60 seconds. | double |
| gcp.gke.node.ephemeral_storage.allocatable_bytes.value | Local ephemeral storage bytes allocatable on the node. Sampled every 60 seconds. | long |
| gcp.gke.node.ephemeral_storage.inodes_free.value | Free number of inodes on local ephemeral storage. Sampled every 60 seconds. | long |
| gcp.gke.node.ephemeral_storage.inodes_total.value | Total number of inodes on local ephemeral storage. Sampled every 60 seconds. | long |
| gcp.gke.node.ephemeral_storage.total_bytes.value | Total ephemeral storage bytes on the node. Sampled every 60 seconds. | long |
| gcp.gke.node.ephemeral_storage.used_bytes.value | Local ephemeral storage bytes used by the node. Sampled every 60 seconds. | long |
| gcp.gke.node.memory.allocatable_bytes.value | Cumulative memory bytes used by the node. Sampled every 60 seconds. | long |
| gcp.gke.node.memory.allocatable_utilization.value | The fraction of the allocatable memory that is currently in use on the instance. This value cannot exceed 1 as usage cannot exceed allocatable memory bytes. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | double |
| gcp.gke.node.memory.total_bytes.value | Number of bytes of memory allocatable on the node. Sampled every 60 seconds. | long |
| gcp.gke.node.memory.used_bytes.value | Cumulative memory bytes used by the node. Sampled every 60 seconds. | long |
| gcp.gke.node.network.received_bytes_count.value | Cumulative number of bytes received by the node over the network. Sampled every 60 seconds. | long |
| gcp.gke.node.network.sent_bytes_count.value | Cumulative number of bytes transmitted by the node over the network. Sampled every 60 seconds. | long |
| gcp.gke.node.pid_limit.value | The max PID of OS on the node. Sampled every 60 seconds. | long |
| gcp.gke.node.pid_used.value | The number of running process in the OS on the node. Sampled every 60 seconds. | long |
| gcp.gke.node_daemon.cpu.core_usage_time.value | Cumulative CPU usage on all cores used by the node level system daemon in seconds. Sampled every 60 seconds. | double |
| gcp.gke.node_daemon.memory.used_bytes.value | Memory usage by the system daemon in bytes. Sampled every 60 seconds. | long |
| gcp.gke.pod.network.received_bytes_count.value | Cumulative number of bytes received by the pod over the network. Sampled every 60 seconds. | long |
| gcp.gke.pod.network.sent_bytes_count.value | Cumulative number of bytes transmitted by the pod over the network. Sampled every 60 seconds. | long |
| gcp.gke.pod.volume.total_bytes.value | Total number of disk bytes available to the pod. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | long |
| gcp.gke.pod.volume.used_bytes.value | Number of disk bytes used by the pod. Sampled every 60 seconds. | long |
| gcp.gke.pod.volume.utilization.value | The fraction of the volume that is currently being used by the instance. This value cannot be greater than 1 as usage cannot exceed the total available volume space. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | double |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
