## Metrics

### container

This is the `container` dataset of the Kubernetes package. It collects container related metrics
from Kubelet's monitoring APIs.

An example event for `container` looks as following:

```$json
{
    "@timestamp": "2020-06-25T12:32:29.748Z",
    "kubernetes": {
        "namespace": "kube-system",
        "node": {
            "name": "minikube"
        },
        "pod": {
            "name": "metricbeat-g9fc6"
        },
        "container": {
            "rootfs": {
                "used": {
                    "bytes": 61440
                },
                "inodes": {
                    "used": 17
                },
                "available": {
                    "bytes": 6724222976
                },
                "capacity": {
                    "bytes": 17361141760
                }
            },
            "logs": {
                "used": {
                    "bytes": 1617920
                },
                "inodes": {
                    "count": 9768928,
                    "used": 223910,
                    "free": 9545018
                },
                "available": {
                    "bytes": 6724222976
                },
                "capacity": {
                    "bytes": 17361141760
                }
            },
            "start_time": "2020-06-25T07:19:37Z",
            "name": "metricbeat",
            "cpu": {
                "usage": {
                    "node": {
                        "pct": 0.00015289625
                    },
                    "limit": {
                        "pct": 0.00015289625
                    },
                    "nanocores": 611585,
                    "core": {
                        "ns": 12206519774
                    }
                }
            },
            "memory": {
                "pagefaults": 10164,
                "majorpagefaults": 528,
                "available": {
                    "bytes": 188600320
                },
                "usage": {
                    "limit": {
                        "pct": 0.005608354460473573
                    },
                    "bytes": 94306304,
                    "node": {
                        "pct": 0.005608354460473573
                    }
                },
                "workingset": {
                    "bytes": 21114880
                },
                "rss": {
                    "bytes": 18386944
                }
            }
        }
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
        "hostname": "minikube",
        "architecture": "x86_64",
        "os": {
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)"
        },
        "name": "minikube",
        "id": "b0e83d397c054b8a99a431072fe4617b"
    },
    "agent": {
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
        "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
        "name": "minikube"
    },
    "metricset": {
        "period": 10000,
        "name": "container"
    },
    "service": {
        "address": "minikube:10250",
        "type": "kubernetes"
    },
    "event": {
        "dataset": "kubernetes.container",
        "module": "kubernetes",
        "duration": 11091346
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
| kubernetes.container.cpu.usage.core.ns | Container CPU Core usage nanoseconds | long |
| kubernetes.container.cpu.usage.limit.pct | CPU usage as a percentage of the defined limit for the container (or total node allocatable CPU if unlimited) | scaled_float |
| kubernetes.container.cpu.usage.nanocores | CPU used nanocores | long |
| kubernetes.container.cpu.usage.node.pct | CPU usage as a percentage of the total node allocatable CPU | scaled_float |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.logs.available.bytes | Logs available capacity in bytes | long |
| kubernetes.container.logs.capacity.bytes | Logs total capacity in bytes | long |
| kubernetes.container.logs.inodes.count | Total available inodes | long |
| kubernetes.container.logs.inodes.free | Total free inodes | long |
| kubernetes.container.logs.inodes.used | Total used inodes | long |
| kubernetes.container.logs.used.bytes | Logs used capacity in bytes | long |
| kubernetes.container.memory.available.bytes | Total available memory | long |
| kubernetes.container.memory.majorpagefaults | Number of major page faults | long |
| kubernetes.container.memory.pagefaults | Number of page faults | long |
| kubernetes.container.memory.rss.bytes | RSS memory usage | long |
| kubernetes.container.memory.usage.bytes | Total memory usage | long |
| kubernetes.container.memory.usage.limit.pct | Memory usage as a percentage of the defined limit for the container (or total node allocatable memory if unlimited) | scaled_float |
| kubernetes.container.memory.usage.node.pct | Memory usage as a percentage of the total node allocatable memory | scaled_float |
| kubernetes.container.memory.workingset.bytes | Working set memory usage | long |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.container.rootfs.available.bytes | Root filesystem total available in bytes | long |
| kubernetes.container.rootfs.capacity.bytes | Root filesystem total capacity in bytes | long |
| kubernetes.container.rootfs.inodes.used | Used inodes | long |
| kubernetes.container.rootfs.used.bytes | Root filesystem total used in bytes | long |
| kubernetes.container.start_time | Start time | date |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.labels.* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.pod.ip | Kubernetes pod IP | ip |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.selectors.* | Kubernetes Service selectors map | object |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
