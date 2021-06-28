## Metrics

### state_node

This is the `state_node` dataset of the Kubernetes package. It collects node related
metrics from `kube_state_metrics`.

An example event for `state_node` looks as following:

```$json
{
    "@timestamp": "2020-06-25T12:37:44.457Z",
    "ecs": {
        "version": "1.5.0"
    },
    "host": {
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux"
        },
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ]
    },
    "metricset": {
        "name": "state_node",
        "period": 10000
    },
    "kubernetes": {
        "node": {
            "pod": {
                "capacity": {
                    "total": 110
                },
                "allocatable": {
                    "total": 110
                }
            },
            "memory": {
                "capacity": {
                    "bytes": 16815325184
                },
                "allocatable": {
                    "bytes": 16815325184
                }
            },
            "cpu": {
                "allocatable": {
                    "cores": 4
                },
                "capacity": {
                    "cores": 4
                }
            },
            "name": "minikube",
            "status": {
                "ready": "true",
                "unschedulable": false
            }
        },
        "labels": {
            "kubernetes_io/arch": "amd64",
            "kubernetes_io/hostname": "minikube",
            "kubernetes_io/os": "linux",
            "node-role_kubernetes_io/master": "",
            "beta_kubernetes_io/arch": "amd64",
            "beta_kubernetes_io/os": "linux"
        }
    },
    "agent": {
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "service": {
        "type": "kubernetes",
        "address": "kube-state-metrics:8080"
    },
    "event": {
        "dataset": "kubernetes.node",
        "module": "kubernetes",
        "duration": 8194220
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
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
| ecs.version | ECS version | keyword |
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
| kubernetes.annotations.* | Kubernetes annotations map | object |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.labels.* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.cpu.allocatable.cores | Node CPU allocatable cores | float |
| kubernetes.node.cpu.capacity.cores | Node CPU capacity cores | long |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.memory.allocatable.bytes | Node allocatable memory in bytes | long |
| kubernetes.node.memory.capacity.bytes | Node memory capacity in bytes | long |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.node.pod.allocatable.total | Node allocatable pods | long |
| kubernetes.node.pod.capacity.total | Node pod capacity | long |
| kubernetes.node.status.disk_pressure | Node DiskPressure status (true, false or unknown) | keyword |
| kubernetes.node.status.memory_pressure | Node MemoryPressure status (true, false or unknown) | keyword |
| kubernetes.node.status.out_of_disk | Node OutOfDisk status (true, false or unknown) | keyword |
| kubernetes.node.status.pid_pressure | Node PIDPressure status (true, false or unknown) | keyword |
| kubernetes.node.status.ready | Node ready status (true, false or unknown) | keyword |
| kubernetes.node.status.unschedulable | Node unschedulable status | boolean |
| kubernetes.pod.ip | Kubernetes pod IP | ip |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.selectors.* | Kubernetes Service selectors map | object |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
