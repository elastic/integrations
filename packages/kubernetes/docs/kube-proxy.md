# kube-proxy

## Metrics

### proxy

This is the `proxy` dataset of the Kubernetes package. It collects metrics
from Kubernetes Proxy component.

An example event for `proxy` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:35:29.639Z",
    "agent": {
        "name": "minikube",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
        "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a"
    },
    "host": {
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
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false
    },
    "kubernetes": {
        "proxy": {
            "sync": {
                "rules": {
                    "duration": {
                        "us": {
                            "sum": 763620.9329999998,
                            "count": 18,
                            "bucket": {
                                "1000": 0,
                                "2000": 0,
                                "4000": 0,
                                "8000": 0,
                                "16000": 0,
                                "32000": 10,
                                "64000": 16,
                                "128000": 17,
                                "256000": 18,
                                "512000": 18,
                                "1024000": 18,
                                "2048000": 18,
                                "4096000": 18,
                                "8192000": 18,
                                "16384000": 18,
                                "+Inf": 18
                            }
                        }
                    }
                },
                "networkprogramming": {
                    "duration": {
                        "us": {
                            "count": 19,
                            "bucket": {
                                "0": 0,
                                "250000": 4,
                                "500000": 8,
                                "1000000": 11,
                                "2000000": 11,
                                "3000000": 11,
                                "4000000": 11,
                                "5000000": 11,
                                "6000000": 11,
                                "7000000": 11,
                                "8000000": 11,
                                "9000000": 11,
                                "10000000": 11,
                                "11000000": 11,
                                "12000000": 11,
                                "13000000": 11,
                                "14000000": 11,
                                "15000000": 11,
                                "16000000": 11,
                                "17000000": 11,
                                "18000000": 11,
                                "19000000": 11,
                                "20000000": 11,
                                "21000000": 11,
                                "22000000": 11,
                                "23000000": 11,
                                "24000000": 11,
                                "25000000": 11,
                                "26000000": 11,
                                "27000000": 11,
                                "28000000": 11,
                                "29000000": 11,
                                "30000000": 11,
                                "31000000": 11,
                                "32000000": 11,
                                "33000000": 11,
                                "34000000": 11,
                                "35000000": 11,
                                "36000000": 11,
                                "37000000": 11,
                                "38000000": 11,
                                "39000000": 11,
                                "40000000": 11,
                                "41000000": 11,
                                "42000000": 11,
                                "43000000": 11,
                                "44000000": 11,
                                "45000000": 11,
                                "46000000": 11,
                                "47000000": 11,
                                "48000000": 11,
                                "49000000": 11,
                                "50000000": 11,
                                "51000000": 11,
                                "52000000": 11,
                                "53000000": 11,
                                "54000000": 11,
                                "55000000": 11,
                                "56000000": 11,
                                "57000000": 11,
                                "58000000": 11,
                                "59000000": 11,
                                "60000000": 11,
                                "65000000": 11,
                                "70000000": 11,
                                "75000000": 11,
                                "80000000": 11,
                                "85000000": 11,
                                "90000000": 11,
                                "95000000": 11,
                                "100000000": 11,
                                "105000000": 11,
                                "110000000": 11,
                                "115000000": 11,
                                "120000000": 11,
                                "150000000": 11,
                                "180000000": 11,
                                "210000000": 11,
                                "240000000": 11,
                                "270000000": 11,
                                "300000000": 11,
                                "+Inf": 19
                            },
                            "sum": 5571080914163.27
                        }
                    }
                }
            },
            "process": {
                "cpu": {
                    "sec": 8
                },
                "memory": {
                    "resident": {
                        "bytes": 37609472
                    },
                    "virtual": {
                        "bytes": 143990784
                    }
                },
                "started": {
                    "sec": 1593069580.69
                },
                "fds": {
                    "open": {
                        "count": 17
                    }
                }
            }
        }
    },
    "ecs": {
        "version": "1.5.0"
    },
    "event": {
        "module": "kubernetes",
        "duration": 2031254,
        "dataset": "kubernetes.proxy"
    },
    "metricset": {
        "name": "proxy",
        "period": 10000
    },
    "service": {
        "address": "localhost:10249",
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
| kubernetes.proxy.client.request.count | Number of requests as client | long |  | counter |
| kubernetes.proxy.code | HTTP code | keyword |  |  |
| kubernetes.proxy.handler | Request handler | keyword |  |  |
| kubernetes.proxy.host | Request host | keyword |  |  |
| kubernetes.proxy.http.request.count | Request count | long |  | counter |
| kubernetes.proxy.http.request.duration.us.count | Request count for duration | long | micros | counter |
| kubernetes.proxy.http.request.duration.us.percentile.\* | Request duration microseconds percentiles | object |  |  |
| kubernetes.proxy.http.request.duration.us.sum | Request duration microseconds cumulative sum | double | micros | counter |
| kubernetes.proxy.http.request.size.bytes.count | Request count for size | long | byte | counter |
| kubernetes.proxy.http.request.size.bytes.percentile.\* | Request size percentiles | object |  |  |
| kubernetes.proxy.http.request.size.bytes.sum | Request size cumulative sum | long | byte | counter |
| kubernetes.proxy.http.response.size.bytes.count | Response count | long |  | counter |
| kubernetes.proxy.http.response.size.bytes.percentile.\* | Response size percentiles | object |  |  |
| kubernetes.proxy.http.response.size.bytes.sum | Response size cumulative sum | long | byte | counter |
| kubernetes.proxy.method | HTTP method | keyword |  |  |
| kubernetes.proxy.process.cpu.sec | CPU seconds | double |  | counter |
| kubernetes.proxy.process.fds.open.count | Number of open file descriptors | long |  | gauge |
| kubernetes.proxy.process.memory.resident.bytes | Bytes in resident memory | long | byte | gauge |
| kubernetes.proxy.process.memory.virtual.bytes | Bytes in virtual memory | long | byte | gauge |
| kubernetes.proxy.process.started.sec | Seconds since the process started | double |  | gauge |
| kubernetes.proxy.sync.networkprogramming.duration.us.bucket.\* | Network programming duration, histogram buckets | object |  |  |
| kubernetes.proxy.sync.networkprogramming.duration.us.count | Network programming duration, number of operations | long |  | counter |
| kubernetes.proxy.sync.networkprogramming.duration.us.sum | Network programming duration, sum in microseconds | long |  | counter |
| kubernetes.proxy.sync.rules.duration.us.bucket.\* | SyncProxyRules duration, histogram buckets | object |  |  |
| kubernetes.proxy.sync.rules.duration.us.count | SyncProxyRules duration, number of operations | long |  | counter |
| kubernetes.proxy.sync.rules.duration.us.sum | SyncProxyRules duration, sum of durations in microseconds | long |  | counter |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
