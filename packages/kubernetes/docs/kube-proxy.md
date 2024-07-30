# kube-proxy

## Metrics

### proxy

This is the `proxy` dataset of the Kubernetes package. It collects metrics
from Kubernetes Proxy component.

An example event for `proxy` looks as following:

```json
{
    "kubernetes": {
        "proxy": {
            "process": {
                "memory": {
                    "virtual": {
                        "bytes": 773107712
                    },
                    "resident": {
                        "bytes": 42229760
                    }
                },
                "fds": {
                    "max": {
                        "count": 1048576
                    },
                    "open": {
                        "count": 16
                    }
                },
                "cpu": {
                    "sec": 0
                },
                "started": {
                    "sec": 1673362810.64
                }
            },
            "sync": {
                "rules": {
                    "duration": {
                        "us": {
                            "bucket": {
                                "1000": 0,
                                "2000": 0,
                                "4000": 0,
                                "8000": 0,
                                "16000": 0,
                                "32000": 0,
                                "64000": 3,
                                "128000": 3,
                                "256000": 4,
                                "512000": 4,
                                "1024000": 4,
                                "2048000": 4,
                                "4096000": 4,
                                "8192000": 4,
                                "16384000": 4,
                                "+Inf": 4
                            },
                            "count": 4,
                            "sum": 353392.43200000003
                        }
                    }
                },
                "networkprogramming": {
                    "duration": {
                        "us": {
                            "bucket": {
                                "0": 0,
                                "250000": 0,
                                "500000": 0,
                                "1000000": 0,
                                "2000000": 0,
                                "3000000": 0,
                                "4000000": 0,
                                "5000000": 0,
                                "6000000": 0,
                                "7000000": 0,
                                "8000000": 0,
                                "9000000": 0,
                                "10000000": 0,
                                "11000000": 0,
                                "12000000": 0,
                                "13000000": 0,
                                "14000000": 0,
                                "15000000": 0,
                                "16000000": 0,
                                "17000000": 0,
                                "18000000": 0,
                                "19000000": 0,
                                "20000000": 0,
                                "21000000": 0,
                                "22000000": 0,
                                "23000000": 0,
                                "24000000": 0,
                                "25000000": 0,
                                "26000000": 0,
                                "27000000": 0,
                                "28000000": 0,
                                "29000000": 0,
                                "30000000": 0,
                                "31000000": 0,
                                "32000000": 0,
                                "33000000": 0,
                                "34000000": 0,
                                "35000000": 0,
                                "36000000": 0,
                                "37000000": 0,
                                "38000000": 0,
                                "39000000": 0,
                                "40000000": 0,
                                "41000000": 0,
                                "42000000": 0,
                                "43000000": 0,
                                "44000000": 0,
                                "45000000": 0,
                                "46000000": 0,
                                "47000000": 0,
                                "48000000": 0,
                                "49000000": 0,
                                "50000000": 0,
                                "51000000": 0,
                                "52000000": 0,
                                "53000000": 0,
                                "54000000": 0,
                                "55000000": 0,
                                "56000000": 0,
                                "57000000": 0,
                                "58000000": 0,
                                "59000000": 0,
                                "60000000": 0,
                                "65000000": 0,
                                "70000000": 0,
                                "75000000": 0,
                                "80000000": 0,
                                "85000000": 0,
                                "90000000": 0,
                                "95000000": 0,
                                "100000000": 0,
                                "105000000": 0,
                                "110000000": 0,
                                "115000000": 0,
                                "120000000": 0,
                                "150000000": 0,
                                "180000000": 0,
                                "210000000": 0,
                                "240000000": 0,
                                "270000000": 0,
                                "300000000": 0,
                                "+Inf": 0
                            },
                            "count": 0,
                            "sum": 0
                        }
                    }
                }
            }
        }
    },
    "orchestrator": {
        "cluster": {
            "name": "kind",
            "url": "kind-control-plane:6443"
        }
    },
    "agent": {
        "name": "kind-control-plane",
        "id": "ee1d778a-e607-4c29-b152-f6e83e606966",
        "type": "metricbeat",
        "ephemeral_id": "084bb5dd-df70-4127-9a52-47fae69de446",
        "version": "8.7.0"
    },
    "@timestamp": "2023-01-10T15:12:38.884Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kubernetes.proxy"
    },
    "service": {
        "address": "http://localhost:10249/metrics",
        "type": "kubernetes"
    },
    "host": {
        "hostname": "kind-control-plane",
        "os": {
            "kernel": "5.15.49-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "family": "debian",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "10.244.0.1",
            "10.244.0.1",
            "10.244.0.1",
            "172.20.0.2",
            "172.18.0.2",
            "fc00:f853:ccd:e793::2",
            "fe80::42:acff:fe12:2"
        ],
        "name": "kind-control-plane",
        "id": "1c1d736687984c73b6a5f77c1464d4da",
        "mac": [
            "02-42-AC-12-00-02",
            "02-42-AC-14-00-02",
            "6E-87-97-B3-C4-A1",
            "7E-2B-73-DA-CF-B7",
            "F2-54-31-F4-76-AB"
        ],
        "architecture": "x86_64"
    },
    "elastic_agent": {
        "id": "ee1d778a-e607-4c29-b152-f6e83e606966",
        "version": "8.7.0",
        "snapshot": true
    },
    "metricset": {
        "period": 10000,
        "name": "proxy"
    },
    "event": {
        "duration": 7214755,
        "agent_id_status": "verified",
        "ingested": "2023-01-10T15:12:39Z",
        "module": "kubernetes",
        "dataset": "kubernetes.proxy"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.proxy.client.request.count | Number of HTTP requests to API server, broken down by status code, method and host | long |  | counter |
| kubernetes.proxy.client.request.duration.us.bucket.\* | Requests latency distribution in histogram buckets, broken down by verb and host | object |  |  |
| kubernetes.proxy.client.request.duration.us.count | Number of request duration operations to API server, broken down by verb and host | long |  | counter |
| kubernetes.proxy.client.request.duration.us.sum | Sum of requests latency in microseconds, broken down by verb and host | long | micros | counter |
| kubernetes.proxy.client.request.size.bytes.bucket.\* | Requests size distribution in histogram buckets, broken down by verb and host | object |  |  |
| kubernetes.proxy.client.request.size.bytes.count | Number of requests, broken down by verb and host | long |  | counter |
| kubernetes.proxy.client.request.size.bytes.sum | Requests size sum in bytes, broken down by verb and host | long | byte | counter |
| kubernetes.proxy.client.response.size.bytes.bucket.\* | Responses size distribution in histogram buckets, broken down by verb and host | object |  |  |
| kubernetes.proxy.client.response.size.bytes.count | Number of responses, broken down by verb and host | long |  | counter |
| kubernetes.proxy.client.response.size.bytes.sum | Responses size sum in bytes, broken down by verb and host | long | byte | counter |
| kubernetes.proxy.code | HTTP code | keyword |  |  |
| kubernetes.proxy.host | HTTP host | keyword |  |  |
| kubernetes.proxy.method | HTTP method | keyword |  |  |
| kubernetes.proxy.process.cpu.sec | Total user and system CPU time spent in seconds | double |  | counter |
| kubernetes.proxy.process.fds.max.count | Limit for open file descriptors | long |  | gauge |
| kubernetes.proxy.process.fds.open.count | Number of open file descriptors | long |  | gauge |
| kubernetes.proxy.process.memory.resident.bytes | Bytes in resident memory | long | byte | gauge |
| kubernetes.proxy.process.memory.virtual.bytes | Bytes in virtual memory | long | byte | gauge |
| kubernetes.proxy.process.started.sec | Start time of the process since unix epoch in seconds | double |  | gauge |
| kubernetes.proxy.sync.networkprogramming.duration.us.bucket.\* | Network programming latency distribution in histogram buckets | object |  |  |
| kubernetes.proxy.sync.networkprogramming.duration.us.count | Number of network programming latency operations | long |  | counter |
| kubernetes.proxy.sync.networkprogramming.duration.us.sum | Sum of network programming latency in microseconds | long |  | counter |
| kubernetes.proxy.sync.rules.duration.us.bucket.\* | SyncProxyRules latency distribution in histogram buckets | object |  |  |
| kubernetes.proxy.sync.rules.duration.us.count | Number of SyncProxyRules latency operations | long |  | counter |
| kubernetes.proxy.sync.rules.duration.us.sum | SyncProxyRules latency sum in microseconds | long |  | counter |
| kubernetes.proxy.verb | HTTP verb | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
