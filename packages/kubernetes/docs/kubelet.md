# kubelet

## Metrics

### container

This is the `container` dataset of the Kubernetes package. It collects container related metrics
from Kubelet's monitoring APIs.

An example event for `container` looks as following:

```json
{
    "kubernetes": {
        "container": {
            "start_time": "2021-12-20T08:47:19Z",
            "memory": {
                "rss": {
                    "bytes": 1433051136
                },
                "majorpagefaults": 297,
                "usage": {
                    "node": {
                        "pct": 0.1533557671938445
                    },
                    "bytes": 1521139712,
                    "limit": {
                        "pct": 0.1533557671938445
                    }
                },
                "available": {
                    "bytes": 0
                },
                "workingset": {
                    "bytes": 1490817024,
                    "limit": {
                        "pct": 0.15029874419
                    }
                },
                "pagefaults": 589314
            },
            "rootfs": {
                "inodes": {
                    "used": 402
                },
                "available": {
                    "bytes": 138514030592
                },
                "used": {
                    "bytes": 15679488
                },
                "capacity": {
                    "bytes": 211108732928
                }
            },
            "name": "elasticsearch",
            "cpu": {
                "usage": {
                    "core": {
                        "ns": 163198143819
                    },
                    "node": {
                        "pct": 0.001825555375
                    },
                    "limit": {
                        "pct": 0.001825555375
                    },
                    "nanocores": 14604443
                }
            },
            "logs": {
                "inodes": {
                    "count": 13107200,
                    "used": 2,
                    "free": 10806621
                },
                "available": {
                    "bytes": 138514030592
                },
                "used": {
                    "bytes": 446464
                },
                "capacity": {
                    "bytes": 211108732928
                }
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
            "uid": "75b5af67-2eed-42d2-8dfc-2a07a9f36c36",
            "ip": "10.244.0.3",
            "name": "elasticsearch-d5cbc495-f5rjf"
        },
        "namespace": "default",
        "namespace_uid": "7cbf170c-6b3a-4b2b-8cfa-2da764bce351",
        "replicaset": {
            "name": "elasticsearch-d5cbc495"
        },
        "namespace_labels": {
            "kubernetes_io/metadata_name": "default"
        },
        "labels": {
            "app": "elasticsearch",
            "pod-template-hash": "d5cbc495"
        },
        "deployment": {
            "name": "elasticsearch"
        }
    },
    "agent": {
        "name": "kind-control-plane",
        "id": "de42127b-4db8-4471-824e-a7b14f478663",
        "type": "metricbeat",
        "ephemeral_id": "09fcf6b0-b25f-4c29-ab3f-179ee664bfae",
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
    "@timestamp": "2021-12-20T09:53:30.156Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kubernetes.container"
    },
    "service": {
        "address": "https://kind-control-plane:10250/stats/summary",
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
        "name": "container"
    },
    "event": {
        "duration": 156057406,
        "agent_id_status": "verified",
        "ingested": "2021-12-20T09:53:30Z",
        "module": "kubernetes",
        "dataset": "kubernetes.container"
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
| container.cpu.usage | Total CPU usage normalized by the number of CPU cores. | scaled_float | percent | gauge |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.memory.usage | Memory usage percentage. | scaled_float | percent | gauge |
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
| kubernetes.container.cpu.usage.core.ns | Container CPU Core usage nanoseconds | long |  | gauge |
| kubernetes.container.cpu.usage.limit.pct | CPU usage as a percentage of the defined limit for the container (or total node allocatable CPU if unlimited) | scaled_float | percent | gauge |
| kubernetes.container.cpu.usage.nanocores | CPU used nanocores | long |  | gauge |
| kubernetes.container.cpu.usage.node.pct | CPU usage as a percentage of the total node allocatable CPU | scaled_float | percent | gauge |
| kubernetes.container.image | Kubernetes container image | keyword |  |  |
| kubernetes.container.logs.available.bytes | Logs available capacity in bytes | long | byte | gauge |
| kubernetes.container.logs.capacity.bytes | Logs total capacity in bytes | long | byte | gauge |
| kubernetes.container.logs.inodes.count | Total available inodes | long |  | gauge |
| kubernetes.container.logs.inodes.free | Total free inodes | long |  | gauge |
| kubernetes.container.logs.inodes.used | Total used inodes | long |  | gauge |
| kubernetes.container.logs.used.bytes | Logs used capacity in bytes | long | byte | gauge |
| kubernetes.container.memory.available.bytes | Total available memory | long | byte | gauge |
| kubernetes.container.memory.majorpagefaults | Number of major page faults | long |  | counter |
| kubernetes.container.memory.pagefaults | Number of page faults | long |  | counter |
| kubernetes.container.memory.rss.bytes | RSS memory usage | long | byte | gauge |
| kubernetes.container.memory.usage.bytes | Total memory usage | long | byte | gauge |
| kubernetes.container.memory.usage.limit.pct | Memory usage as a percentage of the defined limit for the container (or total node allocatable memory if unlimited) | scaled_float | percent | gauge |
| kubernetes.container.memory.usage.node.pct | Memory usage as a percentage of the total node allocatable memory | scaled_float | percent | gauge |
| kubernetes.container.memory.workingset.bytes | Working set memory usage | long | byte | gauge |
| kubernetes.container.memory.workingset.limit.pct | Working set memory usage as a percentage of the defined limit for the container (or total node allocatable memory if unlimited) | scaled_float | percent | gauge |
| kubernetes.container.name | Kubernetes container name | keyword |  |  |
| kubernetes.container.rootfs.available.bytes | Root filesystem total available in bytes | long | byte | gauge |
| kubernetes.container.rootfs.capacity.bytes | Root filesystem total capacity in bytes | long | byte | gauge |
| kubernetes.container.rootfs.inodes.used | Used inodes | long |  | gauge |
| kubernetes.container.rootfs.used.bytes | Root filesystem total used in bytes | long | byte | gauge |
| kubernetes.container.start_time | Start time | date |  |  |
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


### node

This is the `node` dataset of the Kubernetes package. It collects Node related metrics
from Kubelet's monitoring APIs.

An example event for `node` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:34:39.723Z",
    "event": {
        "dataset": "kubernetes.node",
        "module": "kubernetes",
        "duration": 13042307
    },
    "service": {
        "type": "kubernetes",
        "address": "minikube:10250"
    },
    "host": {
        "containerized": false,
        "ip": [
            "192.168.64.10",
            "fe80::a883:2fff:fe7f:6b12",
            "172.17.0.1",
            "fe80::42:d4ff:fe8c:9493",
            "fe80::2859:80ff:fe9e:fcd6",
            "fe80::d83a:d9ff:fee9:7052",
            "fe80::880a:b6ff:fe18:ba76",
            "fe80::f447:faff:fe80:e88b",
            "fe80::9cc3:ffff:fe95:e48e",
            "fe80::6c1c:29ff:fe50:d40c",
            "fe80::b4f3:11ff:fe60:14ed",
            "fe80::20f2:2aff:fe96:1e7b",
            "fe80::5434:baff:fede:5720",
            "fe80::a878:91ff:fe29:81f7"
        ],
        "mac": [
            "aa:83:2f:7f:6b:12",
            "02:42:d4:8c:94:93",
            "2a:59:80:9e:fc:d6",
            "da:3a:d9:e9:70:52",
            "8a:0a:b6:18:ba:76",
            "f6:47:fa:80:e8:8b",
            "9e:c3:ff:95:e4:8e",
            "6e:1c:29:50:d4:0c",
            "b6:f3:11:60:14:ed",
            "22:f2:2a:96:1e:7b",
            "56:34:ba:de:57:20",
            "aa:78:91:29:81:f7"
        ],
        "name": "minikube",
        "hostname": "minikube",
        "architecture": "x86_64",
        "os": {
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81"
        },
        "id": "b0e83d397c054b8a99a431072fe4617b"
    },
    "metricset": {
        "name": "node",
        "period": 10000
    },
    "kubernetes": {
        "labels": {
            "beta_kubernetes_io/os": "linux",
            "kubernetes_io/arch": "amd64",
            "kubernetes_io/hostname": "minikube",
            "kubernetes_io/os": "linux",
            "node-role_kubernetes_io/master": "",
            "beta_kubernetes_io/arch": "amd64"
        },
        "node": {
            "memory": {
                "available": {
                    "bytes": 12746428416
                },
                "usage": {
                    "bytes": 5670916096
                },
                "workingset": {
                    "bytes": 4068896768
                },
                "rss": {
                    "bytes": 3252125696
                },
                "pagefaults": 31680,
                "majorpagefaults": 0
            },
            "network": {
                "rx": {
                    "bytes": 107077476,
                    "errors": 0
                },
                "tx": {
                    "bytes": 67457933,
                    "errors": 0
                }
            },
            "fs": {
                "available": {
                    "bytes": 6655090688
                },
                "capacity": {
                    "bytes": 17361141760
                },
                "used": {
                    "bytes": 9689358336
                },
                "inodes": {
                    "count": 9768928,
                    "used": 224151,
                    "free": 9544777
                }
            },
            "runtime": {
                "imagefs": {
                    "capacity": {
                        "bytes": 17361141760
                    },
                    "used": {
                        "bytes": 8719928568
                    },
                    "available": {
                        "bytes": 6655090688
                    }
                }
            },
            "start_time": "2020-06-25T07:18:38Z",
            "name": "minikube",
            "cpu": {
                "usage": {
                    "core": {
                        "ns": 6136184971873
                    },
                    "nanocores": 455263291
                }
            }
        }
    },
    "agent": {
        "name": "minikube",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
        "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a"
    },
    "ecs": {
        "version": "1.5.0"
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
| kubernetes.node.cpu.usage.core.ns | Node CPU Core usage nanoseconds | long |  | gauge |
| kubernetes.node.cpu.usage.nanocores | CPU used nanocores | long |  | gauge |
| kubernetes.node.fs.available.bytes | Filesystem total available in bytes | long | byte | gauge |
| kubernetes.node.fs.capacity.bytes | Filesystem total capacity in bytes | long | byte | gauge |
| kubernetes.node.fs.inodes.count | Number of inodes | long |  | gauge |
| kubernetes.node.fs.inodes.free | Number of free inodes | long |  | gauge |
| kubernetes.node.fs.inodes.used | Number of used inodes | long |  | gauge |
| kubernetes.node.fs.used.bytes | Filesystem total used in bytes | long | byte | gauge |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.memory.available.bytes | Total available memory | long | byte | gauge |
| kubernetes.node.memory.majorpagefaults | Number of major page faults | long |  | counter |
| kubernetes.node.memory.pagefaults | Number of page faults | long |  | counter |
| kubernetes.node.memory.rss.bytes | RSS memory usage | long | byte | gauge |
| kubernetes.node.memory.usage.bytes | Total memory usage | long | byte | gauge |
| kubernetes.node.memory.workingset.bytes | Working set memory usage | long | byte | gauge |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.node.network.rx.bytes | Received bytes | long | byte | counter |
| kubernetes.node.network.rx.errors | Rx errors | long |  |  |
| kubernetes.node.network.tx.bytes | Transmitted bytes | long | byte | counter |
| kubernetes.node.network.tx.errors | Tx errors | long |  | counter |
| kubernetes.node.runtime.imagefs.available.bytes | Image filesystem total available in bytes | long | byte | gauge |
| kubernetes.node.runtime.imagefs.capacity.bytes | Image filesystem total capacity in bytes | long | byte | gauge |
| kubernetes.node.runtime.imagefs.used.bytes | Image filesystem total used in bytes | long | byte | gauge |
| kubernetes.node.start_time | Start time | date |  |  |
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


### pod

This is the `pod` dataset of the Kubernetes package. It collects Pod related metrics
from Kubelet's monitoring APIs.

An example event for `pod` looks as following:

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
            "start_time": "2021-12-20T08:47:13Z",
            "uid": "9a8de23e-5e64-462f-8576-f6591fb3f7b8",
            "memory": {
                "rss": {
                    "bytes": 64204800
                },
                "major_page_faults": 792,
                "usage": {
                    "node": {
                        "pct": 0.011827949440812145
                    },
                    "bytes": 117321728,
                    "limit": {
                        "pct": 0.011827949440812145
                    }
                },
                "available": {
                    "bytes": 0
                },
                "page_faults": 27027,
                "working_set": {
                    "bytes": 96862208,
                    "limit": {
                        "pct": 0.00976529512
                    }
                }
            },
            "ip": "172.20.0.2",
            "name": "kube-controller-manager-kind-control-plane",
            "cpu": {
                "usage": {
                    "node": {
                        "pct": 0.001893070125
                    },
                    "limit": {
                        "pct": 0.001893070125
                    },
                    "nanocores": 15144561
                }
            },
            "network": {
                "tx": {
                    "bytes": 0,
                    "errors": 0
                },
                "rx": {
                    "bytes": 0,
                    "errors": 0
                }
            }
        },
        "namespace": "kube-system",
        "namespace_uid": "a4453575-518e-4a21-9909-34874f674177",
        "namespace_labels": {
            "kubernetes_io/metadata_name": "kube-system"
        },
        "labels": {
            "component": "kube-controller-manager",
            "tier": "control-plane"
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
    "@timestamp": "2021-12-20T09:59:45.257Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "address": "https://kind-control-plane:10250/stats/summary",
        "type": "kubernetes"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kubernetes.pod"
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
        "name": "pod"
    },
    "event": {
        "duration": 1041186,
        "agent_id_status": "verified",
        "ingested": "2021-12-20T09:59:45Z",
        "module": "kubernetes",
        "dataset": "kubernetes.pod"
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
| container.network.egress.bytes | Total number of outgoing bytes. | long |  | counter |
| container.network.ingress.bytes | Total number of incoming bytes. | long |  | counter |
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
| kubernetes.pod.cpu.usage.limit.pct | CPU usage as a percentage of the defined limit for the pod containers (or total node CPU if one or more containers of the pod are unlimited) | scaled_float | percent | gauge |
| kubernetes.pod.cpu.usage.nanocores | CPU used nanocores | long | byte | gauge |
| kubernetes.pod.cpu.usage.node.pct | CPU usage as a percentage of the total node CPU | scaled_float | percent | gauge |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.memory.available.bytes | Total memory available | long | percent | gauge |
| kubernetes.pod.memory.major_page_faults | Total major page faults | long |  | counter |
| kubernetes.pod.memory.page_faults | Total page faults | long |  | counter |
| kubernetes.pod.memory.rss.bytes | Total resident set size memory | long | percent | gauge |
| kubernetes.pod.memory.usage.bytes | Total memory usage | long | byte | gauge |
| kubernetes.pod.memory.usage.limit.pct | Memory usage as a percentage of the defined limit for the pod containers (or total node allocatable memory if unlimited) | scaled_float | percent | gauge |
| kubernetes.pod.memory.usage.node.pct | Memory usage as a percentage of the total node allocatable memory | scaled_float | percent | gauge |
| kubernetes.pod.memory.working_set.bytes | Total working set memory | long | percent | gauge |
| kubernetes.pod.memory.working_set.limit.pct | Working set memory usage as a percentage of the defined limit for the pod containers (or total node allocatable memory if unlimited) | scaled_float | percent | gauge |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.network.rx.bytes | Received bytes | long | byte | counter |
| kubernetes.pod.network.rx.errors | Rx errors | long |  | counter |
| kubernetes.pod.network.tx.bytes | Transmitted bytes | long | byte | counter |
| kubernetes.pod.network.tx.errors | Tx errors | long |  | counter |
| kubernetes.pod.start_time | Start time | date |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### system

This is the `system` dataset of the Kubernetes package. It collects System related metrics
from Kubelet's monitoring APIs.

An example event for `system` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:39:59.647Z",
    "service": {
        "address": "minikube:10250",
        "type": "kubernetes"
    },
    "event": {
        "duration": 20012905,
        "dataset": "kubernetes.system",
        "module": "kubernetes"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "host": {
        "mac": [
            "aa:83:2f:7f:6b:12",
            "02:42:d4:8c:94:93",
            "2a:59:80:9e:fc:d6",
            "da:3a:d9:e9:70:52",
            "8a:0a:b6:18:ba:76",
            "f6:47:fa:80:e8:8b",
            "9e:c3:ff:95:e4:8e",
            "6e:1c:29:50:d4:0c",
            "b6:f3:11:60:14:ed",
            "22:f2:2a:96:1e:7b",
            "56:34:ba:de:57:20",
            "aa:78:91:29:81:f7"
        ],
        "hostname": "minikube",
        "name": "minikube",
        "architecture": "x86_64",
        "os": {
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos"
        },
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "192.168.64.10",
            "fe80::a883:2fff:fe7f:6b12",
            "172.17.0.1",
            "fe80::42:d4ff:fe8c:9493",
            "fe80::2859:80ff:fe9e:fcd6",
            "fe80::d83a:d9ff:fee9:7052",
            "fe80::880a:b6ff:fe18:ba76",
            "fe80::f447:faff:fe80:e88b",
            "fe80::9cc3:ffff:fe95:e48e",
            "fe80::6c1c:29ff:fe50:d40c",
            "fe80::b4f3:11ff:fe60:14ed",
            "fe80::20f2:2aff:fe96:1e7b",
            "fe80::5434:baff:fede:5720",
            "fe80::a878:91ff:fe29:81f7"
        ]
    },
    "agent": {
        "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
        "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
        "name": "minikube",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "kubernetes": {
        "node": {
            "name": "minikube"
        },
        "system": {
            "container": "runtime",
            "cpu": {
                "usage": {
                    "nanocores": 35779815,
                    "core": {
                        "ns": 530899961233
                    }
                }
            },
            "memory": {
                "pagefaults": 12944019,
                "majorpagefaults": 99,
                "usage": {
                    "bytes": 198279168
                },
                "workingset": {
                    "bytes": 178794496
                },
                "rss": {
                    "bytes": 125259776
                }
            },
            "start_time": "2020-06-25T07:19:32Z"
        }
    },
    "metricset": {
        "name": "system",
        "period": 10000
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
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| kubernetes.system.container | Container name | keyword |  |  |
| kubernetes.system.cpu.usage.core.ns | CPU Core usage nanoseconds | long |  | gauge |
| kubernetes.system.cpu.usage.nanocores | CPU used nanocores | long |  | gauge |
| kubernetes.system.memory.majorpagefaults | Number of major page faults | long |  | counter |
| kubernetes.system.memory.pagefaults | Number of page faults | long |  | counter |
| kubernetes.system.memory.rss.bytes | RSS memory usage | long | byte | gauge |
| kubernetes.system.memory.usage.bytes | Total memory usage | long | byte | gauge |
| kubernetes.system.memory.workingset.bytes | Working set memory usage | long | byte | gauge |
| kubernetes.system.start_time | Start time | date |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### volume

This is the `volume` dataset of the Kubernetes package. It collects Volume related metrics
from Kubelet's monitoring APIs.

An example event for `volume` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:40:19.649Z",
    "ecs": {
        "version": "1.5.0"
    },
    "metricset": {
        "name": "volume",
        "period": 10000
    },
    "service": {
        "type": "kubernetes",
        "address": "minikube:10250"
    },
    "kubernetes": {
        "pod": {
            "name": "metricbeat-g9fc6"
        },
        "volume": {
            "name": "config",
            "fs": {
                "inodes": {
                    "used": 5,
                    "free": 9549949,
                    "count": 9768928,
                    "pct": 0.1533557671938445
                },
                "available": {
                    "bytes": 7719858176
                },
                "capacity": {
                    "bytes": 17361141760
                },
                "used": {
                    "bytes": 12288
                }
            }
        },
        "namespace": "kube-system",
        "node": {
            "name": "minikube"
        }
    },
    "host": {
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
        "containerized": false,
        "ip": [
            "192.168.64.10",
            "fe80::a883:2fff:fe7f:6b12",
            "172.17.0.1",
            "fe80::42:d4ff:fe8c:9493",
            "fe80::2859:80ff:fe9e:fcd6",
            "fe80::d83a:d9ff:fee9:7052",
            "fe80::880a:b6ff:fe18:ba76",
            "fe80::f447:faff:fe80:e88b",
            "fe80::9cc3:ffff:fe95:e48e",
            "fe80::6c1c:29ff:fe50:d40c",
            "fe80::b4f3:11ff:fe60:14ed",
            "fe80::20f2:2aff:fe96:1e7b",
            "fe80::5434:baff:fede:5720",
            "fe80::a878:91ff:fe29:81f7"
        ],
        "name": "minikube",
        "mac": [
            "aa:83:2f:7f:6b:12",
            "02:42:d4:8c:94:93",
            "2a:59:80:9e:fc:d6",
            "da:3a:d9:e9:70:52",
            "8a:0a:b6:18:ba:76",
            "f6:47:fa:80:e8:8b",
            "9e:c3:ff:95:e4:8e",
            "6e:1c:29:50:d4:0c",
            "b6:f3:11:60:14:ed",
            "22:f2:2a:96:1e:7b",
            "56:34:ba:de:57:20",
            "aa:78:91:29:81:f7"
        ],
        "hostname": "minikube"
    },
    "agent": {
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
        "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
        "name": "minikube"
    },
    "event": {
        "dataset": "kubernetes.volume",
        "module": "kubernetes",
        "duration": 12481688
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
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| kubernetes.volume.fs.available.bytes | Filesystem total available in bytes | long | byte | gauge |
| kubernetes.volume.fs.capacity.bytes | Filesystem total capacity in bytes | long | byte | gauge |
| kubernetes.volume.fs.inodes.count | Total inodes | long |  | gauge |
| kubernetes.volume.fs.inodes.free | Free inodes | long |  | gauge |
| kubernetes.volume.fs.inodes.pct | Percentage of used inodes | scaled_float | percent | gauge |
| kubernetes.volume.fs.inodes.used | Used inodes | long |  | gauge |
| kubernetes.volume.fs.used.bytes | Filesystem total used in bytes | long | byte | gauge |
| kubernetes.volume.fs.used.pct | Percentage of filesystem total used | scaled_float | percent | gauge |
| kubernetes.volume.name | Volume name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
