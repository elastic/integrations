## Metrics

### node

This is the `node` dataset of the Kubernetes package. It collects Node related metrics
from Kubelet's monitoring APIs.

An example event for `node` looks as following:

```$json
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
| kubernetes.node.cpu.usage.core.ns | Node CPU Core usage nanoseconds | long |
| kubernetes.node.cpu.usage.nanocores | CPU used nanocores | long |
| kubernetes.node.fs.available.bytes | Filesystem total available in bytes | long |
| kubernetes.node.fs.capacity.bytes | Filesystem total capacity in bytes | long |
| kubernetes.node.fs.inodes.count | Number of inodes | long |
| kubernetes.node.fs.inodes.free | Number of free inodes | long |
| kubernetes.node.fs.inodes.used | Number of used inodes | long |
| kubernetes.node.fs.used.bytes | Filesystem total used in bytes | long |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.memory.available.bytes | Total available memory | long |
| kubernetes.node.memory.majorpagefaults | Number of major page faults | long |
| kubernetes.node.memory.pagefaults | Number of page faults | long |
| kubernetes.node.memory.rss.bytes | RSS memory usage | long |
| kubernetes.node.memory.usage.bytes | Total memory usage | long |
| kubernetes.node.memory.workingset.bytes | Working set memory usage | long |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.node.network.rx.bytes | Received bytes | long |
| kubernetes.node.network.rx.errors | Rx errors | long |
| kubernetes.node.network.tx.bytes | Transmitted bytes | long |
| kubernetes.node.network.tx.errors | Tx errors | long |
| kubernetes.node.runtime.imagefs.available.bytes | Image filesystem total available in bytes | long |
| kubernetes.node.runtime.imagefs.capacity.bytes | Image filesystem total capacity in bytes | long |
| kubernetes.node.runtime.imagefs.used.bytes | Image filesystem total used in bytes | long |
| kubernetes.node.start_time | Start time | date |
| kubernetes.pod.ip | Kubernetes pod IP | ip |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.selectors.* | Kubernetes Service selectors map | object |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
