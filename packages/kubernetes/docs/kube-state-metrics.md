# kube-state-metrics

Kube-state Metrics version should be aligned with the Kubernetes version of your cluster. Follow  relevant [kubernetes/kube-state-metrics compatibility-matrix](https://github.com/kubernetes/kube-state-metrics#compatibility-matrix) for more information.

## Metrics

If Leader Election is activated (default behaviour) only the `elastic agent` which holds the leadership lock
will retrieve metrics from the `kube_state_metrics`.
This is relevant in multi-node kubernetes cluster and prevents duplicate data.

### state_container

This is the `state_container` dataset of the Kubernetes package. It collects container related
metrics from `kube_state_metrics`.

An example event for `state_container` looks as following:

```json
{
    "container": {
        "image": {
            "name": "k8s.gcr.io/coredns/coredns:v1.8.0"
        },
        "runtime": "containerd",
        "id": "696963fe4eeb8734a10e44e0ef8d582fe9861c13ef7c50d6fa5689733df7d302"
    },
    "kubernetes": {
        "container": {
            "memory": {
                "request": {
                    "bytes": 73400320
                },
                "limit": {
                    "bytes": 178257920
                }
            },
            "name": "coredns",
            "cpu": {
                "request": {
                    "cores": 0.1
                }
            },
            "id": "containerd://696963fe4eeb8734a10e44e0ef8d582fe9861c13ef7c50d6fa5689733df7d302",
            "status": {
                "phase": "running",
                "ready": true,
                "restarts": 5
            }
        },
        "node": {
            "uid": "57ccd748-c877-4be9-9b0e-568e9f205025",
            "hostname": "kind-control-plane",
            "name": "kind-control-plane",
            "labels": {
                "node_kubernetes_io/exclude-from-external-load-balancers": "",
                "node-role_kubernetes_io/master": "",
                "kubernetes_io/hostname": "kind-control-plane",
                "node-role_kubernetes_io/control-plane": "",
                "beta_kubernetes_io/os": "linux",
                "kubernetes_io/arch": "amd64",
                "kubernetes_io/os": "linux",
                "beta_kubernetes_io/arch": "amd64"
            }
        },
        "pod": {
            "uid": "b5637989-65ec-4f86-a13e-b9bd02e9bac5",
            "ip": "10.244.0.5",
            "name": "coredns-558bd4d5db-8qp4d"
        },
        "namespace": "kube-system",
        "namespace_uid": "a4453575-518e-4a21-9909-34874f674177",
        "replicaset": {
            "name": "coredns-558bd4d5db"
        },
        "namespace_labels": {
            "kubernetes_io/metadata_name": "kube-system"
        },
        "labels": {
            "pod-template-hash": "558bd4d5db",
            "k8s-app": "kube-dns"
        },
        "deployment": {
            "name": "coredns"
        }
    },
    "agent": {
        "name": "kind-control-plane",
        "id": "de42127b-4db8-4471-824e-a7b14f478663",
        "ephemeral_id": "22ed892c-43bd-408a-9121-65e2f5b6a56e",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "de42127b-4db8-4471-824e-a7b14f478663",
        "version": "8.1.0",
        "snapshot": true
    },
    "orchestrator": {
        "cluster": {
            "name": "kind",
            "url": "kind-control-plane:6443"
        }
    },
    "@timestamp": "2021-12-20T10:02:04.923Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kubernetes.state_container"
    },
    "service": {
        "address": "http://kube-state-metrics:8080/metrics",
        "type": "kubernetes"
    },
    "host": {
        "hostname": "kind-control-plane",
        "os": {
            "kernel": "5.10.47-linuxkit",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "10.244.0.1"
        ],
        "name": "kind-control-plane",
        "id": "85e35c2b5e1b39ba72393a6baf6ee7cd",
        "mac": [
            "fe:ec:82:9f:29:19"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "state_container"
    },
    "event": {
        "duration": 1459222,
        "agent_id_status": "verified",
        "ingested": "2021-12-20T10:02:05Z",
        "module": "kubernetes",
        "dataset": "kubernetes.state_container"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| container.runtime | Runtime managing this container. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |  |
| kubernetes.container.cpu.limit.cores | Container CPU cores limit | float |  | gauge |
| kubernetes.container.cpu.limit.nanocores | Container CPU nanocores limit | long |  | gauge |
| kubernetes.container.cpu.request.cores | Container CPU requested cores | float |  | gauge |
| kubernetes.container.cpu.request.nanocores | Container CPU requested nanocores | long |  | gauge |
| kubernetes.container.id | Container id | keyword |  |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |  |
| kubernetes.container.memory.limit.bytes | Container memory limit in bytes | long | byte | gauge |
| kubernetes.container.memory.request.bytes | Container requested memory in bytes | long | byte | gauge |
| kubernetes.container.name | Kubernetes container name | keyword |  |  |
| kubernetes.container.status.phase | Container phase (running, waiting, terminated) | keyword |  |  |
| kubernetes.container.status.ready | Container ready status | boolean |  |  |
| kubernetes.container.status.reason | Waiting (ContainerCreating, CrashLoopBackoff, ErrImagePull, ImagePullBackoff) or termination (Completed, ContainerCannotRun, Error, OOMKilled) reason. | keyword |  |  |
| kubernetes.container.status.restarts | Container restarts count | integer |  | counter |
| kubernetes.cronjob.name | Name of the CronJob to which the Pod belongs | keyword |  |  |
| kubernetes.daemonset.name | Kubernetes daemonset name | keyword |  |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |  |
| kubernetes.job.name | Name of the Job to which the Pod belongs | keyword |  |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |  |
| kubernetes.namespace_annotations.\* | Kubernetes namespace annotations map | object |  |  |
| kubernetes.namespace_labels.\* | Kubernetes namespace labels map | object |  |  |
| kubernetes.namespace_uid | Kubernetes namespace UID | keyword |  |  |
| kubernetes.node.annotations.\* | Kubernetes node annotations map | object |  |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.labels.\* | Kubernetes node labels map | object |  |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.node.uid | Kubernetes node UID | keyword |  |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### state_cronjob

This is the `state_cronjob` dataset of the Kubernetes package. It collects cronjob related
metrics from `kube_state_metrics`.

>Important Note: Please make sure that you install latest kube-state metrics version for this datataset to appear. 
Eg. Kube-state-metrics v2.3.0 was not reporting cron_job metrics for Kubernetes v1.25.0

An example event for `state_cronjob` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:43:04.384Z",
    "metricset": {
        "name": "state_cronjob",
        "period": 10000
    },
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "host": {
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)"
        }
    },
    "event": {
        "dataset": "kubernetes.cronjob",
        "module": "kubernetes",
        "duration": 9482053
    },
    "kubernetes": {
        "namespace": "default",
        "cronjob": {
            "active": {
                "count": 0
            },
            "is_suspended": false,
            "name": "hello",
            "next_schedule": {
                "sec": 1593088980
            },
            "last_schedule": {
                "sec": 1593088920
            },
            "created": {
                "sec": 1593088862
            }
        }
    },
    "agent": {
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |  |
| kubernetes.cronjob.active.count | Number of active pods for the cronjob | long |  | gauge |
| kubernetes.cronjob.concurrency | Concurrency policy | keyword |  |  |
| kubernetes.cronjob.created.sec | Epoch seconds since the cronjob was created | double | s | gauge |
| kubernetes.cronjob.deadline.sec | Deadline seconds after schedule for considering failed | long | s | gauge |
| kubernetes.cronjob.is_suspended | Whether the cronjob is suspended | boolean |  |  |
| kubernetes.cronjob.last_schedule.sec | Epoch seconds for last cronjob run | double | s | gauge |
| kubernetes.cronjob.name | Cronjob name | keyword |  |  |
| kubernetes.cronjob.next_schedule.sec | Epoch seconds for next cronjob run | double | s | gauge |
| kubernetes.cronjob.schedule | Cronjob schedule | keyword |  |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### state_daemonset

This is the `state_daemonset` dataset of the Kubernetes package. It collects daemonset related
metrics from `kube_state_metrics`.

An example event for `state_daemonset` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:37:04.455Z",
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "event": {
        "module": "kubernetes",
        "duration": 8648138,
        "dataset": "kubernetes.daemonset"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "metricset": {
        "name": "state_daemonset",
        "period": 10000
    },
    "kubernetes": {
        "daemonset": {
            "name": "metricbeat",
            "replicas": {
                "available": 1,
                "desired": 1,
                "ready": 1,
                "unavailable": 0
            }
        },
        "labels": {
            "k8s-app": "metricbeat"
        },
        "namespace": "kube-system"
    },
    "host": {
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat"
        },
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ]
    },
    "agent": {
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |
| kubernetes.daemonset.name |  | keyword |  |
| kubernetes.daemonset.replicas.available | The number of available replicas per DaemonSet | long | gauge |
| kubernetes.daemonset.replicas.desired | The desired number of replicas per DaemonSet | long | gauge |
| kubernetes.daemonset.replicas.ready | The number of ready replicas per DaemonSet | long | gauge |
| kubernetes.daemonset.replicas.unavailable | The number of unavailable replicas per DaemonSet | long | gauge |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


### state_deployment

This is the `state_deployment` dataset of the Kubernetes package. It collects deployment related
metrics from `kube_state_metrics`.

An example event for `state_deployment` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:37:04.455Z",
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "event": {
        "module": "kubernetes",
        "duration": 8648138,
        "dataset": "kubernetes.deployment"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "metricset": {
        "name": "state_deployment",
        "period": 10000
    },
    "kubernetes": {
        "deployment": {
            "name": "metricbeat",
            "replicas": {
                "unavailable": 0,
                "desired": 1,
                "updated": 1,
                "available": 1
            },
            "paused": false
        },
        "labels": {
            "k8s-app": "metricbeat"
        },
        "namespace": "kube-system"
    },
    "host": {
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat"
        },
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ]
    },
    "agent": {
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |
| kubernetes.deployment.paused | Kubernetes deployment paused status | boolean |  |
| kubernetes.deployment.replicas.available | Deployment available replicas | integer | gauge |
| kubernetes.deployment.replicas.desired | Deployment number of desired replicas (spec) | integer | gauge |
| kubernetes.deployment.replicas.unavailable | Deployment unavailable replicas | integer | gauge |
| kubernetes.deployment.replicas.updated | Deployment updated replicas | integer | gauge |
| kubernetes.labels.\* | Kubernetes labels map | object |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


### state_job

This is the `state_job` dataset of the Kubernetes package. It collects job related
metrics from `kube_state_metrics`.

An example event for `state_job` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:43:04.384Z",
    "metricset": {
        "name": "state_job",
        "period": 10000
    },
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "host": {
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)"
        }
    },
    "event": {
        "dataset": "kubernetes.job",
        "module": "kubernetes",
        "duration": 9482053
    },
    "kubernetes": {
        "job": {
            "completions": {
                "desired": 1
            },
            "name": "sleep-30-ok-cron-27075645",
            "owner": {
                "is_controller": "true",
                "kind": "CronJob",
                "name": "sleep-30-ok-cron"
            },
            "parallelism": {
                "desired": 1
            },
            "pods": {
                "active": 1,
                "failed": 0,
                "succeeded": 0
            },
            "time": {
                "created": "2021-06-24T12:45:00.000Z"
            }
        },
        "namespace": "default"
    },
    "agent": {
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |
| kubernetes.cronjob.name | Name of the CronJob to which the Pod belongs | keyword |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |
| kubernetes.job.completions.desired | The configured completion count for the job (Spec) | long | gauge |
| kubernetes.job.name | Name of the Job to which the Pod belongs | keyword |  |
| kubernetes.job.owner.is_controller | Owner is controller ("true", "false", or `"\<none\>"`) | keyword |  |
| kubernetes.job.owner.kind | The kind of resource that owns this job (eg. "CronJob") | keyword |  |
| kubernetes.job.owner.name | The name of the resource that owns this job | keyword |  |
| kubernetes.job.parallelism.desired | The configured parallelism of the job (Spec) | long | gauge |
| kubernetes.job.pods.active | Number of active pods | long | gauge |
| kubernetes.job.pods.failed | Number of failed pods | long | gauge |
| kubernetes.job.pods.succeeded | Number of successful pods | long | gauge |
| kubernetes.job.status.complete | Whether the job completed ("true", "false", or "unknown") | keyword |  |
| kubernetes.job.status.failed | Whether the job failed ("true", "false", or "unknown") | keyword |  |
| kubernetes.job.time.completed | The time at which the job completed | date |  |
| kubernetes.job.time.created | The time at which the job was created | date |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


### state_node

This is the `state_node` dataset of the Kubernetes package. It collects node related
metrics from `kube_state_metrics`.

An example event for `state_node` looks as following:

```json
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

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |  |
| kubernetes.node.cpu.allocatable.cores | Node CPU allocatable cores | float |  | gauge |
| kubernetes.node.cpu.capacity.cores | Node CPU capacity cores | long |  | gauge |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.memory.allocatable.bytes | Node allocatable memory in bytes | long | byte | gauge |
| kubernetes.node.memory.capacity.bytes | Node memory capacity in bytes | long | byte | gauge |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.node.pod.allocatable.total | Node allocatable pods | long |  | gauge |
| kubernetes.node.pod.capacity.total | Node pod capacity | long |  | gauge |
| kubernetes.node.status.disk_pressure | Node DiskPressure status (true, false or unknown) | keyword |  |  |
| kubernetes.node.status.memory_pressure | Node MemoryPressure status (true, false or unknown) | keyword |  |  |
| kubernetes.node.status.out_of_disk | Node OutOfDisk status (true, false or unknown) | keyword |  |  |
| kubernetes.node.status.pid_pressure | Node PIDPressure status (true, false or unknown) | keyword |  |  |
| kubernetes.node.status.ready | Node ready status (true, false or unknown) | keyword |  |  |
| kubernetes.node.status.unschedulable | Node unschedulable status | boolean |  |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### state_persistentvolume

This is the `state_persistentvolume` dataset of the Kubernetes package. It collects 
PersistentVolume related metrics from `kube_state_metrics`.

An example event for `state_persistentvolume` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:43:54.412Z",
    "ecs": {
        "version": "1.5.0"
    },
    "event": {
        "module": "kubernetes",
        "duration": 12149615,
        "dataset": "kubernetes.persistentvolume"
    },
    "agent": {
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat"
    },
    "kubernetes": {
        "persistentvolume": {
            "capacity": {
                "bytes": 10737418240
            },
            "phase": "Bound",
            "storage_class": "manual",
            "name": "task-pv-volume"
        },
        "labels": {
            "type": "local"
        }
    },
    "host": {
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81"
        },
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "containerized": false
    },
    "metricset": {
        "period": 10000,
        "name": "state_persistentvolume"
    },
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.persistentvolume.capacity.bytes | Volume capacity | long | byte | gauge |
| kubernetes.persistentvolume.name | Volume name. | keyword |  |  |
| kubernetes.persistentvolume.phase | Volume phase according to kubernetes | keyword |  |  |
| kubernetes.persistentvolume.storage_class | Storage class for the volume | keyword |  |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### state_persistentvolumeclaim

This is the `state_persistentvolumeclaim` dataset of the Kubernetes package. It collects 
PersistentVolumeClaim related metrics from `kube_state_metrics`.

An example event for `state_persistentvolumeclaim` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:44:44.418Z",
    "event": {
        "dataset": "kubernetes.persistentvolumeclaim",
        "module": "kubernetes",
        "duration": 5698588
    },
    "metricset": {
        "name": "state_persistentvolumeclaim",
        "period": 10000
    },
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "kubernetes": {
        "namespace": "default",
        "persistentvolumeclaim": {
            "phase": "Bound",
            "storage_class": "manual",
            "volume_name": "task-pv-volume",
            "name": "task-pv-claim",
            "request_storage": {
                "bytes": 3221225472
            },
            "access_mode": "ReadWriteOnce"
        }
    },
    "agent": {
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "host": {
        "os": {
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core"
        },
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.persistentvolumeclaim.access_mode | Access mode. | keyword |  |  |
| kubernetes.persistentvolumeclaim.name | PVC name. | keyword |  |  |
| kubernetes.persistentvolumeclaim.phase | PVC phase. | keyword |  |  |
| kubernetes.persistentvolumeclaim.request_storage.bytes | Requested capacity. | long | byte | gauge |
| kubernetes.persistentvolumeclaim.storage_class | Storage class for the PVC. | keyword |  |  |
| kubernetes.persistentvolumeclaim.volume_name | Binded volume name. | keyword |  |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### state_pod

This is the `state_pod` dataset of the Kubernetes package. It collects 
Pod related metrics from `kube_state_metrics`.

An example event for `state_pod` looks as following:

```json
{
    "kubernetes": {
        "node": {
            "uid": "57ccd748-c877-4be9-9b0e-568e9f205025",
            "hostname": "kind-control-plane",
            "name": "kind-control-plane",
            "labels": {
                "node_kubernetes_io/exclude-from-external-load-balancers": "",
                "node-role_kubernetes_io/master": "",
                "kubernetes_io/hostname": "kind-control-plane",
                "node-role_kubernetes_io/control-plane": "",
                "beta_kubernetes_io/os": "linux",
                "kubernetes_io/arch": "amd64",
                "kubernetes_io/os": "linux",
                "beta_kubernetes_io/arch": "amd64"
            }
        },
        "pod": {
            "uid": "d06d59c2-929f-4b13-bc7d-c2492200ce07",
            "host_ip": "172.20.0.2",
            "ip": "172.20.0.2",
            "name": "elastic-agent-h2mgj",
            "status": {
                "phase": "running",
                "ready": "true",
                "scheduled": "true"
            }
        },
        "namespace": "kube-system",
        "daemonset": {
            "name": "elastic-agent"
        },
        "namespace_uid": "a4453575-518e-4a21-9909-34874f674177",
        "namespace_labels": {
            "kubernetes_io/metadata_name": "kube-system"
        },
        "labels": {
            "app": "elastic-agent",
            "controller-revision-hash": "57c5d7c56f",
            "pod-template-generation": "3"
        }
    },
    "agent": {
        "name": "kind-control-plane",
        "id": "de42127b-4db8-4471-824e-a7b14f478663",
        "type": "metricbeat",
        "ephemeral_id": "22ed892c-43bd-408a-9121-65e2f5b6a56e",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "de42127b-4db8-4471-824e-a7b14f478663",
        "version": "8.1.0",
        "snapshot": true
    },
    "orchestrator": {
        "cluster": {
            "name": "kind",
            "url": "kind-control-plane:6443"
        }
    },
    "@timestamp": "2021-12-20T10:03:24.643Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kubernetes.state_pod"
    },
    "service": {
        "address": "http://kube-state-metrics:8080/metrics",
        "type": "kubernetes"
    },
    "host": {
        "hostname": "kind-control-plane",
        "os": {
            "kernel": "5.10.47-linuxkit",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "type": "linux",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "10.244.0.1"
        ],
        "name": "kind-control-plane",
        "id": "85e35c2b5e1b39ba72393a6baf6ee7cd",
        "mac": [
            "fe:ec:82:9f:29:19"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "state_pod"
    },
    "event": {
        "duration": 736951,
        "agent_id_status": "verified",
        "ingested": "2021-12-20T10:03:25Z",
        "module": "kubernetes",
        "dataset": "kubernetes.state_pod"
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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| kubernetes.annotations.\* | Kubernetes annotations map | object |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.cronjob.name | Name of the CronJob to which the Pod belongs | keyword |
| kubernetes.daemonset.name | Kubernetes daemonset name | keyword |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.job.name | Name of the Job to which the Pod belongs | keyword |
| kubernetes.labels.\* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.namespace_annotations.\* | Kubernetes namespace annotations map | object |
| kubernetes.namespace_labels.\* | Kubernetes namespace labels map | object |
| kubernetes.namespace_uid | Kubernetes namespace UID | keyword |
| kubernetes.node.annotations.\* | Kubernetes node annotations map | object |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.labels.\* | Kubernetes node labels map | object |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.node.uid | Kubernetes node UID | keyword |
| kubernetes.pod.host_ip | Kubernetes pod host IP | ip |
| kubernetes.pod.ip | Kubernetes pod IP | ip |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.status.phase | Kubernetes pod phase (Running, Pending...) | keyword |
| kubernetes.pod.status.ready | Kubernetes pod ready status (true, false or unknown) | keyword |
| kubernetes.pod.status.scheduled | Kubernetes pod scheduled status (true, false, unknown) | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| orchestrator.cluster.name | Name of the cluster. | keyword |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### state_replicaset

This is the `state_replicaset` dataset of the Kubernetes package. It collects 
Replicaset related metrics from `kube_state_metrics`.

An example event for `state_replicaset` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:38:54.482Z",
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "metricset": {
        "period": 10000,
        "name": "state_replicaset"
    },
    "event": {
        "module": "kubernetes",
        "duration": 5456128,
        "dataset": "kubernetes.replicaset"
    },
    "kubernetes": {
        "namespace": "kube-system",
        "replicaset": {
            "name": "nginx-ingress-controller-6fc5bcc8c9",
            "replicas": {
                "labeled": 1,
                "ready": 1,
                "available": 1,
                "observed": 1,
                "desired": 1
            }
        },
        "deployment": {
            "name": "nginx-ingress-controller"
        },
        "labels": {
            "app_kubernetes_io/part-of": "kube-system",
            "pod-template-hash": "6fc5bcc8c9",
            "addonmanager_kubernetes_io/mode": "Reconcile",
            "app_kubernetes_io/name": "nginx-ingress-controller"
        }
    },
    "agent": {
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "host": {
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core"
        },
        "id": "b0e83d397c054b8a99a431072fe4617b"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |
| kubernetes.replicaset.replicas.available | The number of replicas per ReplicaSet | long | gauge |
| kubernetes.replicaset.replicas.desired | The number of replicas per ReplicaSet | long | gauge |
| kubernetes.replicaset.replicas.labeled | The number of fully labeled replicas per ReplicaSet | long | gauge |
| kubernetes.replicaset.replicas.observed | The generation observed by the ReplicaSet controller | long | gauge |
| kubernetes.replicaset.replicas.ready | The number of ready replicas per ReplicaSet | long | gauge |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


### state_resourcequota

This is the `state_resourcequota` dataset of the Kubernetes package. It collects ResourceQuota related metrics
from `kube_state_metrics`.

An example event for `state_resourcequota` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:45:04.416Z",
    "metricset": {
        "name": "state_resourcequota",
        "period": 10000
    },
    "host": {
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81"
        },
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ]
    },
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "event": {
        "dataset": "kubernetes.resourcequota",
        "module": "kubernetes",
        "duration": 6324269
    },
    "agent": {
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "kubernetes": {
        "namespace": "quota-object-example",
        "resourcequota": {
            "name": "object-quota-demo",
            "resource": "persistentvolumeclaims",
            "type": "hard",
            "quota": 1
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.resourcequota.created.sec | Epoch seconds since the ResourceQuota was created | double | s | gauge |
| kubernetes.resourcequota.name | ResourceQuota name | keyword |  |  |
| kubernetes.resourcequota.quota | Quota informed (hard or used) for the resource | double |  | gauge |
| kubernetes.resourcequota.resource | Resource name the quota applies to | keyword |  |  |
| kubernetes.resourcequota.type | Quota information type, `hard` or `used` | keyword |  |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### state_service

This is the `state_service` dataset of the Kubernetes package. It collects 
Service related metrics from `kube_state_metrics`.

An example event for `state_service` looks as following:

```json
{
    "kubernetes": {
        "service": {
            "created": "2021-12-15T16:57:18.000Z",
            "name": "kube-dns",
            "type": "ClusterIP",
            "cluster_ip": "10.96.0.10"
        },
        "namespace": "kube-system",
        "namespace_uid": "a4453575-518e-4a21-9909-34874f674177",
        "selectors": {
            "k8s-app": "kube-dns"
        },
        "namespace_labels": {
            "kubernetes_io/metadata_name": "kube-system"
        },
        "labels": {
            "kubernetes_io_cluster_service": "true",
            "kubernetes_io_name": "CoreDNS",
            "k8s_app": "kube-dns",
            "k8s-app": "kube-dns",
            "kubernetes_io/cluster-service": "true",
            "kubernetes_io/name": "CoreDNS"
        }
    },
    "agent": {
        "name": "kind-control-plane",
        "id": "de42127b-4db8-4471-824e-a7b14f478663",
        "type": "metricbeat",
        "ephemeral_id": "22ed892c-43bd-408a-9121-65e2f5b6a56e",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "de42127b-4db8-4471-824e-a7b14f478663",
        "version": "8.1.0",
        "snapshot": true
    },
    "orchestrator": {
        "cluster": {
            "name": "kind",
            "url": "kind-control-plane:6443"
        }
    },
    "@timestamp": "2021-12-20T10:04:34.632Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "address": "http://kube-state-metrics:8080/metrics",
        "type": "kubernetes"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kubernetes.state_service"
    },
    "host": {
        "hostname": "kind-control-plane",
        "os": {
            "kernel": "5.10.47-linuxkit",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "10.244.0.1"
        ],
        "name": "kind-control-plane",
        "id": "85e35c2b5e1b39ba72393a6baf6ee7cd",
        "mac": [
            "fe:ec:82:9f:29:19"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "state_service"
    },
    "event": {
        "duration": 187211,
        "agent_id_status": "verified",
        "ingested": "2021-12-20T10:04:35Z",
        "module": "kubernetes",
        "dataset": "kubernetes.state_service"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| kubernetes.annotations.\* | Kubernetes annotations map | object |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.labels.\* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.namespace_annotations.\* | Kubernetes namespace annotations map | object |
| kubernetes.namespace_labels.\* | Kubernetes namespace labels map | object |
| kubernetes.namespace_uid | Kubernetes namespace UID | keyword |
| kubernetes.pod.ip | Kubernetes pod IP | ip |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |
| kubernetes.service.cluster_ip | Internal IP for the service. | keyword |
| kubernetes.service.created | Service creation date | date |
| kubernetes.service.external_ip | Service external IP | keyword |
| kubernetes.service.external_name | Service external DNS name | keyword |
| kubernetes.service.ingress_hostname | Ingress Hostname | keyword |
| kubernetes.service.ingress_ip | Ingress IP | keyword |
| kubernetes.service.load_balancer_ip | Load Balancer service IP | keyword |
| kubernetes.service.name | Service name. | keyword |
| kubernetes.service.type | Service type | keyword |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| orchestrator.cluster.name | Name of the cluster. | keyword |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### state_statefulset

This is the `state_statefulset` dataset of the Kubernetes package.

An example event for `state_statefulset` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:39:24.389Z",
    "kubernetes": {
        "namespace": "default",
        "statefulset": {
            "created": 1511989697,
            "generation": {
                "desired": 4,
                "observed": 2
            },
            "name": "mysql",
            "replicas": {
                "desired": 5,
                "observed": 2
            }
        }
    },
    "event": {
        "dataset": "kubernetes.statefulset",
        "module": "kubernetes",
        "duration": 10966648
    },
    "metricset": {
        "name": "state_statefulset",
        "period": 10000
    },
    "host": {
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "os": {
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core"
        }
    },
    "agent": {
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |
| kubernetes.statefulset.created | The creation timestamp (epoch) for StatefulSet | long | gauge |
| kubernetes.statefulset.generation.desired | The desired generation per StatefulSet | long | gauge |
| kubernetes.statefulset.generation.observed | The observed generation per StatefulSet | long | gauge |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |
| kubernetes.statefulset.replicas.desired | The number of desired replicas per StatefulSet | long | gauge |
| kubernetes.statefulset.replicas.observed | The number of observed replicas per StatefulSet | long | gauge |
| kubernetes.statefulset.replicas.ready | The number of ready replicas per StatefulSet | long | gauge |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


### state_storageclass

This is the `state_storageclass` dataset of the Kubernetes package. It collects 
StorageClass related metrics from `kube_state_metrics`.

An example event for `state_storageclass` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:39:44.399Z",
    "agent": {
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee"
    },
    "kubernetes": {
        "storageclass": {
            "provisioner": "k8s.io/minikube-hostpath",
            "reclaim_policy": "Delete",
            "volume_binding_mode": "Immediate",
            "name": "standard",
            "created": "2020-06-10T09:02:27.000Z"
        },
        "labels": {
            "addonmanager_kubernetes_io_mode": "EnsureExists"
        }
    },
    "host": {
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core"
        },
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ]
    },
    "event": {
        "module": "kubernetes",
        "duration": 5713503,
        "dataset": "kubernetes.storageclass"
    },
    "metricset": {
        "name": "state_storageclass",
        "period": 10000
    },
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "ecs": {
        "version": "1.5.0"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| kubernetes.annotations.\* | Kubernetes annotations map | object |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.labels.\* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.pod.ip | Kubernetes pod IP | ip |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| kubernetes.storageclass.created | Storage class creation date | date |
| kubernetes.storageclass.name | Storage class name. | keyword |
| kubernetes.storageclass.provisioner | Volume provisioner for the storage class. | keyword |
| kubernetes.storageclass.reclaim_policy | Reclaim policy for dynamically created volumes | keyword |
| kubernetes.storageclass.volume_binding_mode | Mode for default provisioning and binding | keyword |
| orchestrator.cluster.name | Name of the cluster. | keyword |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
